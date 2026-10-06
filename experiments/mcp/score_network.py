#!/usr/bin/env python3
"""Independent TCP payload oracle; payloads never participate in attribution."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re


def score(run):
    calls=[json.loads(line) for line in (run/'tool-calls.jsonl').read_text().splitlines()]
    slots={call['arguments']['slot']:call['id'] for call in calls if call['tool']=='tcp_roundtrip'}
    counts=Counter(); seen=Counter(); errors=[]
    for row in map(json.loads,(run/'causal-attribution.jsonl').read_text().splitlines()):
        if not re.match(r'\d+<TCP',row['args']) or (row['return_value'] or 0)<=0:continue
        direction='read' if row['syscall'] in {'read','readv','recvfrom','recvmsg'} else 'write' if row['syscall'] in {'write','writev','sendto','sendmsg'} else None
        if direction is None:continue
        labels=set(map(int,re.findall(r'causpan-net:(\d+)\\n',row['args'])))
        if not labels:continue
        expected={slots[slot] for slot in labels}
        actual=set(row.get('request_ids',[]))
        counts[direction+'_events']+=1
        counts['correct']+=actual==expected
        for request in expected:seen[(request,direction)]+=1
        if expected!=actual:errors.append(dict(source=row['source'],direction=direction,expected=sorted(expected,key=str),actual=sorted(actual,key=str),origin=row['origin']))
    for request in slots.values():
        for direction in ['read','write']:
            if not seen[(request,direction)]:errors.append(dict(request=request,missing=direction))
    result=dict(valid=not errors,counts=dict(counts),mismatches=errors,
                oracle='complete synthetic TCP payload tokens; used only for scoring, not inference')
    (run/'network-score.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    if errors:raise RuntimeError('network attribution mismatch')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('run',type=Path)
    score(parser.parse_args().run.resolve())
