#!/usr/bin/env python3
"""Independent offset oracle: the attributor never consumes this workload information."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re


def score(run):
    scenario=json.loads((run/'run-config.json').read_text()).get('scenario') if (run/'run-config.json').exists() else None
    calls=list(map(json.loads,(run/'tool-calls.jsonl').read_text().splitlines()))
    slots={c['arguments']['slot']:c for c in calls if 'slot' in c['arguments']}
    rows=list(map(json.loads,(run/'causal-attribution.jsonl').read_text().splitlines()))
    counts=Counter();per_call=Counter();samples=[]
    worker_jobs={};background_by_tid=Counter()
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
        if background and scenario=='worker-failure':
            background_by_tid[row['tid']]+=1
        elif not background and call['tool']=='worker_slot':
            worker_jobs.setdefault(row['tid'],set()).add(str(call['id']))
            if scenario=='worker-failure':
                expected_failed=bool(slot%2)
                if (row['return_value'] is not None and row['return_value']<0)!=expected_failed:
                    samples.append(dict(source=row['source'],error='worker syscall failure mismatch'))
        if not background:
            per_call[str(call['id'])]+=1
            counts['after_response']+=row['timestamp_ns']>call['end_ns']
        if not correct:samples.append(dict(source=row['source'],expected=expected,actual=actual))
    responses={r['message'].get('id'):r['message'].get('result',{}) for r in map(json.loads,(run/'protocol.jsonl').read_text().splitlines()) if r['direction']=='response'}
    for call in slots.values():
        wanted=1 if call['tool'] in {'spawn_slot','cancel_probe','fail_probe'} else 2 if call['tool'] in {'clone_files_slot','worker_slot'} else 2*call['arguments'].get('rounds',3)
        if call['tool']=='worker_slot' and scenario in {'worker-relay','worker-rights'}:wanted=3
        if call['tool']=='worker_slot' and scenario=='worker-failure':
            expected_failure=bool(call['arguments']['slot']%2)
            if bool(responses[call['id']].get('structuredContent',{}).get('expected_failure'))!=expected_failure:
                samples.append(dict(request_id=call['id'],error='worker failure response mismatch'))
            if expected_failure:
                wanted=1
                counts['expected_worker_failures']+=1
        if call['tool']=='worker_slot' and scenario=='worker-cancel':
            cancelled=bool(call['arguments']['slot']%2)
            if bool(responses[call['id']].get('structuredContent',{}).get('cancelled'))!=cancelled:
                samples.append(dict(request_id=call['id'],error='worker cancellation response mismatch'))
            if cancelled:
                wanted=0
                counts['cancelled_requests']+=1
        if call['tool']=='cancel_probe':
            result=responses[call['id']]['structuredContent']
            if result['status']==-125:
                wanted=0;counts['cancelled_requests']+=1
            elif result['status']!=0:raise ValueError(f'probe unexpected result {result}')
        if per_call[str(call['id'])]!=wanted:
            samples.append(dict(request_id=call['id'],expected_events=wanted,observed=per_call[str(call['id'])]))
    if scenario=='worker-socketpair':
        message_counts=Counter()
        for row in rows:
            if row['syscall'] not in {'sendmsg','recvmsg'}:continue
            match=re.search(r'worker-socket:(\d+)',row['args'])
            if not match:continue
            slot=int(match[1]);call=slots.get(slot)
            if call is None:raise ValueError('unknown socketpair oracle slot')
            message_counts[(slot,row['syscall'])]+=1
            counts['socket_message_events']+=1
            if row.get('request_ids')!=[call['id']] or row['attribution']!='bound' or row['return_value']!=len(f'worker-socket:{slot}'):
                samples.append(dict(source=row['source'],error='socketpair payload attribution mismatch'))
        for slot in slots:
            for syscall in ['sendmsg','recvmsg']:
                if message_counts[(slot,syscall)]!=1:
                    samples.append(dict(slot=slot,syscall=syscall,expected_events=1,observed=message_counts[(slot,syscall)]))
    if scenario=='worker-failure':
        for tid,jobs in worker_jobs.items():
            if background_by_tid[tid]!=len(jobs):
                samples.append(dict(tid=tid,expected_background=len(jobs),observed_background=background_by_tid[tid]))
        counts['worker_reset_background_events']=sum(background_by_tid[tid] for tid in worker_jobs)
    report=dict(valid=not samples,counts=dict(counts),mismatches=samples,
                oracle='pread64/pwrite64 byte offsets on one shared path and descriptor; socketpair scenario also uses complete message tokens; neither is used during inference')
    (run/'control-score.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    if samples:raise RuntimeError('independent offset oracle disagrees')
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('run',type=Path)
    score(p.parse_args().run.resolve())
