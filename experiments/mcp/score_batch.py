#!/usr/bin/env python3
"""Independent oracle for one syscall containing contributions from multiple MCP calls."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re


def score(run):
    calls=list(map(json.loads,(run/'tool-calls.jsonl').read_text().splitlines()))
    slots={c['arguments']['slot']:c['id'] for c in calls if c['tool']=='batch_io'}
    counts=Counter();per_call=Counter();errors=[]
    for row in map(json.loads,(run/'causal-attribution.jsonl').read_text().splitlines()):
        if row['syscall']!='pwrite64' or row['paths']!=[str(run/'sandbox/slots.bin')]:continue
        match=re.search(r',\s*(\d+),\s*(\d+)\s*$',row['args'])
        if not match:raise ValueError('unparsed batch write')
        size,offset=map(int,match.groups());first=offset//128
        if first==100000:
            expected=set();counts['background_events']+=1
        else:
            if size%128 or offset%128 or row['return_value']!=size:raise ValueError('partial or unaligned batch write')
            expected={slots[s] for s in range(first,first+size//128)}
            counts['request_events']+=1
            counts['multi_parent_events']+=len(expected)>1
            for request in expected:per_call[request]+=1
        actual=set(row.get('request_ids',[row['request_id']] if row['request_id'] is not None else []))
        counts['expected_parent_edges']+=len(expected)
        counts['correct_parent_edges']+=len(expected&actual)
        counts['false_parent_edges']+=len(actual-expected)
        counts['missing_parent_edges']+=len(expected-actual)
        if actual!=expected:errors.append(dict(source=row['source'],expected=sorted(expected,key=str),actual=sorted(actual,key=str)))
    for slot,request in slots.items():
        if per_call[request]!=1:errors.append(dict(request=request,expected_writes=1,observed=per_call[request]))
    result=dict(valid=not errors,counts=dict(counts),mismatches=errors,
                oracle='batch offset and byte count determine contributing request slots; not used during inference')
    (run/'batch-score.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    if errors:raise RuntimeError('batch parent-set mismatch')
    return result

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('run',type=Path)
    score(p.parse_args().run.resolve())
