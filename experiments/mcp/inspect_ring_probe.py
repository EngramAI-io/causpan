#!/usr/bin/env python3
"""Independent fixture checks plus trace corroboration for the standalone ring probe."""
import argparse
import hashlib
import json
from pathlib import Path
import re
from analyze import parse_traces
from ring_observations import join_observations


def _inspect(run):
    events, quality = parse_traces(run/'traces')
    if any(quality.get(key) for key in ['unparsed','orphan_resumed','incomplete_at_eof']):
        raise ValueError('incomplete or unparsed syscall capture')
    witness = run/'ring-observations.jsonl'
    observed = b''
    for event in events:
        if event['syscall'] != 'write' or event['paths'] != [str(witness)]:
            continue
        match = re.search(r', ("(?:\\.|[^"\\])*"), (\d+)$', event['args'])
        if not match:
            raise ValueError('cannot decode runtime observation write')
        data = json.loads(match[1]).encode()
        if len(data) != int(match[2]) or event['return_value'] != len(data):
            raise ValueError('truncated runtime observation write')
        observed += data
    if observed != witness.read_bytes():
        raise ValueError('runtime observations differ from traced writes')
    rows = [json.loads(line) for line in observed.splitlines()]
    operations = join_observations(rows)
    ring = [e for e in events if e['syscall'].startswith('io_uring_')]
    setups = [e for e in ring if e['syscall']=='io_uring_setup' and e['return_value'] is not None and e['return_value']>=0]
    entries = [e for e in ring if e['syscall']=='io_uring_enter']
    if len(setups)!=1 or len(entries)!=1 or entries[0]['return_value']!=3:
        raise ValueError('unexpected probe ring syscall pattern')
    if int(re.match(r'\d+',entries[0]['args'])[0]) != setups[0]['return_value']:
        raise ValueError('enter refers to another ring')
    effects = (run/'effects.bin').read_bytes()
    if effects != b'uring-A' + bytes(121) + b'uring-B':
        raise ValueError('independent file-content oracle disagrees')
    expected = {101:(0,7),102:(128,7),103:(256,-9)}
    if {o['user_data']:(o['offset'],o['result']) for o in operations} != expected:
        raise ValueError('completion oracle disagrees')
    direct = [e for e in events if e['syscall'] in {'write','writev','pwrite64','pwritev','pwritev2'} and e['paths']==[str(run/'effects.bin')]]
    if direct:
        raise ValueError('probe unexpectedly used direct file-write syscalls')
    report=dict(valid=True,scope='standalone trusted ring observations, no MCP attribution yet',
                parser=quality, operations=operations, ring_syscalls=ring,
                direct_file_write_syscalls=0, independently_verified_file_writes=2,
                traced_runtime_observations_match=True,
                completion_order=[o['user_data'] for o in operations],
                submission_order=[r['user_data'] for r in rows if r['kind']=='sqe'],
                file_sha256=hashlib.sha256(effects).hexdigest(),
                limitations=['CQE/SQE contents are trusted runtime observations, not decoded by strace',
                             'one ring, single-shot READ/WRITE, no flags or user_data reuse',
                             'no kernel worker TID or request ownership established'])
    (run/'ring-report.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def inspect(run):
    try:
        return _inspect(run)
    except Exception as error:
        (run/'ring-report.json').write_text(json.dumps(dict(valid=False, error=str(error)),indent=2)+'\n')
        raise


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('run',type=Path)
    print(json.dumps(inspect(parser.parse_args().run.resolve()),indent=2))
