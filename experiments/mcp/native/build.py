#!/usr/bin/env python3
"""Build a fail-closed, binary-pinned Node instrumentation addon."""
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess

EM_AARCH64 = 183  # ELF machine type for AArch64 (ARM 64-bit); from <linux/elf-em.h>.

root=Path(__file__).resolve().parent
node=Path(shutil.which('node')).resolve()
versions=json.loads(subprocess.check_output([str(node),'-p','JSON.stringify(process.versions)'],text=True))
if versions['node']!='24.20.0' or versions['uv']!='1.52.1':
    raise SystemExit('Unsupported runtime: requires verified Node 24.20.0 / libuv 1.52.1')
elf=node.read_bytes()
if elf[:4]!=b'\x7fELF' or elf[5]!=1 or struct.unpack_from('<HH',elf,16)!=(2,EM_AARCH64):
    raise SystemExit('Requires a non-PIE ELF AArch64 executable; no guessed relocation is allowed')
header=node.parent.parent/'include/node'
if not (header/'node_api.h').exists(): raise SystemExit('Node development headers not found')
symbols=subprocess.check_output(['nm',str(node)],text=True)
address=next(int(line.split()[0],16) for line in symbols.splitlines() if line.endswith(' t uv__work_submit'))
subprocess.run(['g++','-std=c++17','-O2','-Wall','-Wextra','-shared','-fPIC','-pthread',
                '-I'+str(header),str(root/'context.cc'),'-o',str(root/'context.node.tmp')],check=True)
(root/'context.node.tmp').replace(root/'context.node')
manifest=dict(node=str(node),sha256=hashlib.sha256(node.read_bytes()).hexdigest(),
              versions=versions,address=str(address),architecture='aarch64',
              source_sha256=hashlib.sha256((root/'context.cc').read_bytes()).hexdigest())
(root/'build.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(manifest,indent=2))
