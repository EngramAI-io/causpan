#!/usr/bin/env python3
"""Independent offsets/content oracle for MCP ring operations, never inference input."""
import argparse
from collections import Counter
import json
from pathlib import Path


def score(run):
    calls=[json.loads(x) for x in (run/'tool-calls.jsonl').read_text().splitlines()]
    calls=[c for c in calls if c['tool'] in {'uring_slot','worker_slot'}]
    graph=[json.loads(x) for x in (run/'provenance.jsonl').read_text().splitlines()]
    operations=[r for r in graph if r['type']=='node' and r['kind']=='ring_operation']
    expected={}
    errors=[]
    if not calls:errors.append(dict(error='no ring tool calls'))
    settings=json.loads((run/'run-config.json').read_text())
    reuse=settings.get('scenario')=='uring-reuse'
    target=run/'sandbox'/('replacement.bin' if reuse else 'slots.bin')
    data=target.read_bytes()
    original=(run/'sandbox/slots.bin').read_bytes() if reuse else None
    for call in calls:
        base=call['arguments']['slot']*512
        if reuse and (any(original[base:base+7]) or any(original[base+128:base+135])):
            errors.append(dict(request=call['id'],error='prepared descriptor target unexpectedly modified'))
        for index in range(3):
            offset=base+index*128
            if offset in expected:raise ValueError('duplicate oracle slot')
            expected[offset]=(call['id'],22 if index==2 else 23,-9 if index==2 else 7)
        if data[base:base+7]!=b'uring-A' or data[base+128:base+135]!=b'uring-B':
            errors.append(dict(request=call['id'],error='file content mismatch'))
    seen=Counter()
    for operation in operations:
        offset=operation['offset'];seen[offset]+=1
        wanted=expected.get(offset)
        if reuse and operation['opcode']==23 and operation.get('paths')!=[str(target)]:
            errors.append(dict(operation=operation['id'],error='resource retained pre-submission descriptor target'))
        if wanted is None or (operation['request_ids'],operation['opcode'],operation['result'])!=([wanted[0]],wanted[1],wanted[2]):
            errors.append(dict(operation=operation['id'],error='ring ownership or result mismatch'))
    if set(seen)!=set(expected) or any(count!=1 for count in seen.values()):
        errors.append(dict(error='missing or duplicate ring operation'))
    report=dict(valid=not errors,tool_calls=len(calls),ring_operations=len(operations),
                successful_writes=sum(o['opcode']==23 and o['result']==7 for o in operations),
                expected_failed_reads=sum(o['opcode']==22 and o['result']==-9 for o in operations),
                mismatches=errors,oracle='fixture byte offsets and final contents, not used in inference')
    (run/'ring-score.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    if errors:raise ValueError('independent ring oracle disagrees')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('run',type=Path)
    score(parser.parse_args().run.resolve())
