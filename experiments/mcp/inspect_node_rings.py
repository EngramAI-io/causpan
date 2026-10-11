#!/usr/bin/env python3
"""Inventory actual runtime ring entry points before attempting binary hooks."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('output',type=Path)
    run=p.parse_args().output;run.mkdir(parents=True,exist_ok=False)
    node=Path(shutil.which('node')).resolve()
    lines=subprocess.check_output(['nm','-an',str(node)],text=True).splitlines()
    symbols=[]
    for line in lines:
        parts=line.split()
        if len(parts)==3 and (parts[2].startswith('uv__iou') or parts[2].startswith('uv__io_uring') or parts[2]=='uv__io_poll'):
            symbols.append(dict(name=parts[2],address=int(parts[0],16),symbol_type=parts[1]))
    if not symbols:raise RuntimeError('no ring symbols present')
    outputs=[]
    for symbol in symbols:
        name=symbol['name']+'.asm';target=run/name
        target.write_text(subprocess.check_output(['objdump','-d',f'--start-address={symbol["address"]}',f'--stop-address={symbol["address"]+192}',str(node)],text=True))
        outputs.append(dict(file=name,sha256=hashlib.sha256(target.read_bytes()).hexdigest()))
    report=dict(node=str(node),node_sha256=hashlib.sha256(node.read_bytes()).hexdigest(),
                versions=json.loads(subprocess.check_output([str(node),'-p','JSON.stringify(process.versions)'],text=True)),
                symbols=symbols,disassembly=outputs,
                scope='Static inventory only; symbol presence does not establish execution, request ownership, ABI stability, or safe hook placement.')
    (run/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
