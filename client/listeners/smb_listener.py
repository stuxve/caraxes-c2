"""
SMB named pipe listener.

Runs an SMB server (via impacket) that accepts agent connections
on a configurable named pipe. The protocol over the pipe is identical
to the HTTPS listener: framed TLV packets with AES-GCM encryption.

Wire format on pipe: [4 bytes LE: length] [packet bytes]
"""

import asyncio
import logging
import socket
import struct
import threading
from pathlib import Path
from typing import Optional
from uuid import UUID

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


class SmbPipeHandler:
    """
    Handles a single named pipe connection from an agent.
    Called by the impacket SMB server's named pipe handler.
    """

    def __init__(self, listener: "SmbListener"):
        self.listener = listener
        self._buf = bytearray()

    def read_framed(self, data: bytes) -> Optional[bytes]:
        """
        Accumulate data and extract a complete framed message.
        Frame: [4 bytes LE length] [payload]
        Returns payload when complete, None if still accumulating.
        """
        self._buf.extend(data)

        if len(self._buf) < 4:
            return None

        msg_len = struct.unpack_from("<I", self._buf, 0)[0]
        if msg_len > 16 * 1024 * 1024:  # Sanity: 16MB max
            self._buf.clear()
            return None

        total_needed = 4 + msg_len
        if len(self._buf) < total_needed:
            return None

        payload = bytes(self._buf[4:total_needed])
        self._buf = self._buf[total_needed:]
        return payload

    def frame_response(self, data: bytes) -> bytes:
        """Frame a response with 4-byte LE length prefix."""
        return struct.pack("<I", len(data)) + data

    def handle_packet(self, packet: bytes) -> Optional[bytes]:
        """
        Process a complete packet from the agent. Returns response packet.
        This mirrors the HTTPS listener's _handle_request logic.
        """
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


class SmbListener(BaseListener):
    """
    SMB named pipe listener using impacket.

    The listener creates an SMB server that exposes a named pipe.
    Agents connect to \\<ip>\pipe\<pipename> and communicate using
    the same binary protocol as the HTTPS listener.
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
    ):
        super().__init__(listener_id, "SMB", name=name or "SMB")
        self.pipe_name = pipe_name
        self.host = host
        self.session_manager = session_manager
        self.task_manager = task_manager
        self.logger = logger
        self.magic = magic

        self._rsa_private_key = None
        if rsa_private_key_path and rsa_private_key_path.exists():
            self._rsa_private_key = load_private_key(rsa_private_key_path)

        self._server = None
        self._thread: Optional[threading.Thread] = None
        self._tcp_server: Optional[socket.socket] = None
        self._tcp_thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    async def start(self):
        self._loop = asyncio.get_event_loop()

        # ── Local TCP server for impacket pipe forwarding ──
        # impacket's registerNamedPipe maps a pipe name to a TCP
        # address. When an agent opens the pipe, impacket connects
        # to this TCP server and forwards all pipe I/O through it.
        self._tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tcp_server.bind(('127.0.0.1', 0))
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
            self.pipe_name, ('127.0.0.1', tcp_port)
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
        """Handle pipe I/O forwarded from impacket for one agent session."""
        handler = SmbPipeHandler(self)
        conn.settimeout(300)  # 5 min idle timeout
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    break

                # Feed data; process every complete frame in the buffer
                packet = handler.read_framed(data)
                while packet is not None:
                    response = handler.handle_packet(packet)
                    if response is not None:
                        framed = handler.frame_response(response)
                        conn.sendall(framed)
                    # Check for another complete frame already buffered
                    packet = handler.read_framed(b"")
        except socket.timeout:
            log.debug("SMB pipe handler idle timeout")
        except (ConnectionError, OSError) as e:
            log.debug(f"SMB pipe handler closed: {e}")
        finally:
            conn.close()

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

    # ─── Protocol handlers (shared with SmbPipeHandler) ───

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
