#!/usr/bin/env python3
"""Score known write payloads independently of attribution, including atomic temp files."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re


def score(run):
    calls=list(map(json.loads,(run/'tool-calls.jsonl').read_text().splitlines()))
    expected={}
    for call in calls:
        if call['tool']=='write_file':expected[call['arguments']['content']]=call['id']
        elif call['tool']=='edit_file':expected[call['arguments']['edits'][0]['newText']]=call['id']
    counts=Counter();observed=Counter();errors=[]
    for row in map(json.loads,(run/'causal-attribution.jsonl').read_text().splitlines()):
        if row['syscall']!='write' or not any(p.startswith(str(run/'sandbox')+'/') for p in row['paths']):continue
        quoted=re.match(r'\d+<[^>]+>,\s*("(?:\\.|[^"\\])*")',row['args'])
        if not quoted:raise ValueError('unparsed file write payload')
        content=json.loads(quoted[1])
        if content not in expected:raise ValueError('unexpected file payload')
        request=expected[content];observed[request]+=1;counts['labelled_writes']+=1
        correct=row.get('request_ids',[row['request_id']])==[request]
        counts['correct' if correct else 'wrong']+=1
        if not correct:errors.append(dict(source=row['source'],expected=request,actual=row.get('request_ids')))
    for request in expected.values():
        if observed[request]!=1:errors.append(dict(request=request,expected_writes=1,observed=observed[request]))
    result=dict(valid=not errors,counts=dict(counts),mismatches=errors,
                oracle='exact known file write payloads from write_file/edit_file fixture arguments; not used during inference')
    (run/'fileops-score.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    if errors:raise RuntimeError('file operation oracle mismatch')
    return result

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('run',type=Path)
    score(p.parse_args().run.resolve())
