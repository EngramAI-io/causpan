#!/usr/bin/env python3
"""Randomized paired wall-time benchmark, run after other workloads have drained."""
import argparse
import json
from pathlib import Path
import random
import statistics
import subprocess
import sys

HERE=Path(__file__).resolve().parent

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--seccomp',action='store_true')
    p.add_argument('--repeats',type=int,default=5)
    args=p.parse_args();root=args.output.resolve();root.mkdir(parents=True,exist_ok=False)
    cases=[(capture,instrumented,rep) for capture in ['strace','off'] for instrumented in [False,True] for rep in range(args.repeats)]
    random.Random(42).shuffle(cases)
    rows=[]
    for capture,instrumented,rep in cases:
        name=f'{capture}-i{int(instrumented)}-r{rep}';run=root/name
        cmd=[sys.executable,str(HERE/'run.py'),'--output',str(run),'--capture',capture,
             '--concurrency','32','--batches','4']
        if args.seccomp:cmd.append('--seccomp')
        if instrumented:cmd.append('--instrumented')
        with (root/(name+'.log')).open('w') as stream:
            subprocess.run(cmd,stdout=stream,stderr=subprocess.STDOUT,check=True,timeout=180)
        manifest=json.loads((run/'manifest.json').read_text())
        protocol=list(map(json.loads,(run/'protocol.jsonl').read_text().splitlines()))
        starts={r['message']['id']:r['mono_ns'] for r in protocol if r['direction']=='request' and r['message'].get('method')=='tools/call'}
        durations=[(r['mono_ns']-starts[r['message']['id']])/1e6 for r in protocol if r['direction']=='response' and r['message'].get('id') in starts]
        row=dict(name=name,capture=capture,instrumented=instrumented,repeat=rep,
                 execution_seconds=manifest['execution_seconds'],median_call_ms=statistics.median(durations),
                 p95_call_ms=sorted(durations)[int(.95*(len(durations)-1))])
        rows.append(row);(root/'runs.json').write_text(json.dumps(rows,indent=2)+'\n')
        print(f'{len(rows)}/{len(cases)} {name} {row["execution_seconds"]:.3f}s',flush=True)
    summary=[]
    for capture in ['strace','off']:
        base=statistics.median(r['execution_seconds'] for r in rows if r['capture']==capture and not r['instrumented'])
        inst=statistics.median(r['execution_seconds'] for r in rows if r['capture']==capture and r['instrumented'])
        summary.append(dict(capture=capture,baseline_median_seconds=base,instrumented_median_seconds=inst,ratio=inst/base))
    (root/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary,indent=2))

if __name__=='__main__':main()
