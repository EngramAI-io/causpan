#!/usr/bin/env python3
"""Independent offset oracle: the attributor never consumes this workload information."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re


def score(run):
    calls=list(map(json.loads,(run/'tool-calls.jsonl').read_text().splitlines()))
    slots={c['arguments']['slot']:c for c in calls if 'slot' in c['arguments']}
    rows=list(map(json.loads,(run/'causal-attribution.jsonl').read_text().splitlines()))
    counts=Counter();per_call=Counter();samples=[]
    for row in rows:
        if row['syscall'] not in {'pread64','pwrite64'} or row['paths']!=[str(run/'sandbox/slots.bin')]:continue
        match=re.search(r',\s*(\d+)\s*$',row['args'])
        if not match:raise ValueError(f'cannot parse offset at {row["source"]}')
        offset=int(match[1]);slot=offset//128
        if offset%128:raise ValueError(f'unaligned oracle offset {offset}')
        background=slot==100000
        call=slots.get(slot)
        if not background and call is None:raise ValueError(f'unknown slot {slot}')
        expected=None if background else call['id']
        actual=row.get('request_ids',[row['request_id']] if row['request_id'] is not None else [])
        correct=actual==([] if background else [expected]) and row['attribution']!='invalid_capture'
        counts['background' if background else 'request_events']+=1
        counts['correct' if correct else 'wrong']+=1
        if row['return_value'] is not None and row['return_value']<0:counts['failed_syscalls']+=1
        if not background:
            per_call[str(call['id'])]+=1
            counts['after_response']+=row['timestamp_ns']>call['end_ns']
        if not correct:samples.append(dict(source=row['source'],expected=expected,actual=actual))
    responses={r['message'].get('id'):r['message'].get('result',{}) for r in map(json.loads,(run/'protocol.jsonl').read_text().splitlines()) if r['direction']=='response'}
    for call in slots.values():
        wanted=1 if call['tool'] in {'spawn_slot','cancel_probe','fail_probe'} else 2*call['arguments'].get('rounds',3)
        if call['tool']=='cancel_probe':
            result=responses[call['id']]['structuredContent']
            if result['status']==-125:
                wanted=0;counts['cancelled_requests']+=1
            elif result['status']!=0:raise ValueError(f'probe unexpected result {result}')
        if per_call[str(call['id'])]!=wanted:
            samples.append(dict(request_id=call['id'],expected_events=wanted,observed=per_call[str(call['id'])]))
    report=dict(valid=not samples,counts=dict(counts),mismatches=samples,
                oracle='pread64/pwrite64 byte offsets on one shared path and descriptor; not used during inference')
    (run/'control-score.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    if samples:raise RuntimeError('independent offset oracle disagrees')
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('run',type=Path)
    score(p.parse_args().run.resolve())
