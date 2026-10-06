#!/usr/bin/env python3
"""Bounded parallel experiment matrix; every run owns a fresh evidence directory."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import itertools
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--runtime',choices=['node','tokio'],default='node')
    p.add_argument('--runtime-workers',type=int,default=2)
    p.add_argument('--tokio-binary',type=Path)
    p.add_argument('--timeout',type=float,default=180,help='Seconds per run, including analysis')
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--concurrency',default='1,8,32')
    p.add_argument('--pools',default='1,4')
    p.add_argument('--repeats',type=int,default=2)
    p.add_argument('--jobs',type=int,default=2)
    p.add_argument('--scenarios',default='read')
    p.add_argument('--batches',type=int,default=4)
    p.add_argument('--seccomp',action='store_true')
    p.add_argument('--baseline',action='store_true',help='also run without instrumentation')
    args=p.parse_args()
    if args.timeout<=0:p.error('--timeout must be positive')
    root=args.output.resolve();root.mkdir(parents=True,exist_ok=False)
    cases=[]
    for scenario in args.scenarios.split(','):
        cases.extend((*case,scenario) for case in itertools.product(map(int,args.concurrency.split(',')),map(int,args.pools.split(',')),
                    [False,True] if scenario=='read' else [False],range(args.repeats),
                    [False,True] if args.baseline and scenario not in {'cancel','failure'} else [True]))
    def run(case):
        concurrency,pool,shared,repeat,instrumented,scenario=case
        name=f'{scenario}-c{concurrency}-p{pool}-s{int(shared)}-r{repeat}-i{int(instrumented)}'
        path=root/name
        cmd=[sys.executable,str(HERE/'run.py'),'--concurrency',str(concurrency),'--pool-size',str(pool),
             '--runtime',args.runtime,'--runtime-workers',str(args.runtime_workers),'--output',str(path),'--scenario',scenario,'--batches',str(args.batches)]
        if args.seccomp:cmd.append('--seccomp')
        if shared:cmd.append('--shared')
        if instrumented:cmd.append('--instrumented')
        if args.tokio_binary:cmd.extend(['--tokio-binary',str(args.tokio_binary.resolve())])
        start=time.monotonic()
        timed_out=False
        with (root/(name+'.log')).open('w') as out:
            result=subprocess.Popen(cmd,stdout=out,stderr=subprocess.STDOUT,start_new_session=True)
            try:
                result.wait(timeout=args.timeout)
            except subprocess.TimeoutExpired:
                timed_out=True
                # Stop the whole capture tree, not only the Python driver.
                try:os.killpg(result.pid,signal.SIGTERM)
                except ProcessLookupError:pass
                try:result.wait(timeout=5)
                except subprocess.TimeoutExpired:pass
                try:os.killpg(result.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                result.wait()
                path.mkdir(parents=True,exist_ok=True)
                manifest_path=path/'manifest.json'
                manifest=json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
                manifest.update(status='failed',error='matrix timeout',timeout_seconds=args.timeout)
                manifest_path.write_text(json.dumps(manifest,indent=2)+'\n')
        row=dict(name=name,scenario=scenario,runtime=args.runtime,runtime_workers=args.runtime_workers,concurrency=concurrency,pool_size=pool,shared=shared,repeat=repeat,
                 instrumented=instrumented,returncode=124 if timed_out else result.returncode,timed_out=timed_out,elapsed_seconds=time.monotonic()-start)
        for file in ['report','causal-report','control-score','batch-score','fileops-score','network-score','manifest']:
            if (path/(file+'.json')).exists():row[file]=json.loads((path/(file+'.json')).read_text())
        return row
    rows=[]
    with ThreadPoolExecutor(max_workers=args.jobs) as workers:
        for future in as_completed([workers.submit(run,case) for case in cases]):
            row=future.result();rows.append(row)
            temporary=root/'summary.json.tmp'
            temporary.write_text(json.dumps(rows,indent=2)+'\n')
            temporary.replace(root/'summary.json')
            print(f'{len(rows)}/{len(cases)} {row["name"]} exit={row["returncode"]}',flush=True)
    if any(r['returncode'] for r in rows):raise SystemExit(1)

if __name__=='__main__':main()
