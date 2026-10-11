#!/usr/bin/env python3
"""Collector-created ring inherited by a stopped worker; inspect actual shared bytes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from ring_memory_probe import decode
from ring_observations import join_observations, validate_waiting_enter
from analyze import parse_traces


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('output',type=Path)
    run=parser.parse_args().output.resolve();run.mkdir(parents=True,exist_ok=False)
    source=Path(__file__).with_name('io_uring_probe.c');binary=run/'helper'
    subprocess.run(['gcc','-Wall','-Wextra','-Werror','-O2',str(source),'-o',str(binary)],check=True)
    (run/'traces').mkdir()
    with (run/'stdout.jsonl').open('w') as out,(run/'metadata.jsonl').open('w') as err:
        completed=subprocess.run(['strace','-ff','-ttt','-T','-yy','-s','4096','-o',str(run/'traces/strace'),str(binary),str(run/'fixture.bin')],stdout=out,stderr=err,
            env={**os.environ,'CAUSPAN_RING_INHERITED_COLLECTOR':str(run)},timeout=15)
    if completed.returncode:raise RuntimeError('inherited ring collector failed')
    meta=json.loads((run/'metadata.jsonl').read_text())
    records=decode(meta,*[(run/name).read_bytes() for name in ['sq.bin','sqes.bin','cq.bin']])
    operations=join_observations(records)
    for operation in operations:operation['evidence']='parent_snapshot_of_inherited_shared_ring'
    witnesses=[json.loads(line) for line in (run/'stdout.jsonl').read_text().splitlines()]
    if records!=witnesses:raise ValueError('memory observations differ from runtime witnesses')
    data=(run/'fixture.bin').read_bytes()
    if data[:7]!=b'uring-A' or data[128:135]!=b'uring-B':raise ValueError('fixture contents mismatch')
    events,quality=parse_traces(run/'traces')
    setups=[e for e in events if e['syscall']=='io_uring_setup' and e['return_value'] is not None and e['return_value']>=0]
    enters=[e for e in events if e['syscall']=='io_uring_enter']
    if len(setups)!=1 or len(enters)!=1:raise ValueError('expected one setup and enter')
    setup,enter=setups[0],enters[0]
    if validate_waiting_enter(enter,len(operations))!=setup['return_value']:raise ValueError('ring FD mismatch')
    forks=[e for e in events if e['syscall'] in {'clone','clone3','fork'} and e['pid']==setup['pid'] and e['return_value']==enter['pid']]
    if len(forks)!=1 or setup['pid']==enter['pid']:raise ValueError('missing collector to submitter fork')
    if not setup['completion_ns']<=forks[0]['timestamp_ns']<=enter['timestamp_ns']:raise ValueError('inverted ring lifecycle')
    snapshot_writes={}
    for name in ['sq.bin','sqes.bin','cq.bin']:
        writes=[e for e in events if e['pid']==setup['pid'] and e['syscall']=='write' and str(run/name) in e['paths']]
        if len(writes)!=1 or writes[0]['return_value']!=(run/name).stat().st_size:raise ValueError('snapshot write evidence missing')
        snapshot_writes[name]=writes[0]
    if any(snapshot_writes[name]['completion_ns']>enter['timestamp_ns'] for name in ['sq.bin','sqes.bin']):raise ValueError('SQ snapshot follows enter')
    if snapshot_writes['cq.bin']['timestamp_ns']<enter['completion_ns']:raise ValueError('CQ snapshot precedes completion')
    lifecycle=dict(collector_pid=setup['pid'],submitter_pid=enter['pid'],setup=setup['source'],fork=forks[0]['source'],enter=enter['source'],snapshots={n:e['source'] for n,e in snapshot_writes.items()},parser=quality)
    report=dict(valid=True,operations=operations,lifecycle=lifecycle,
        limitations=['collector creates ring before fork','cooperative worker stops','helper provides layout metadata','no MCP ownership or kernel worker identity','not a collector for arbitrary preexisting rings'],
        sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [source,Path(__file__),Path(__file__).with_name('ring_memory_probe.py'),binary,*sorted((run/'traces').glob('strace.*')),*[run/n for n in ['sq.bin','sqes.bin','cq.bin','metadata.jsonl','stdout.jsonl','fixture.bin']]]})
    (run/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

if __name__=='__main__':main()
