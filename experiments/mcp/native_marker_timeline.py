#!/usr/bin/env python3
"""Join trusted marker observations to submission context, not causal ownership."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
from inspect_native_windows import inspect

CONTEXT_KINDS={'JS_CONTEXT','WORK_ENTER','WORK_LEAVE','DONE_ENTER','DONE_LEAVE'}

def report(run):
    log=run/'debugger.log'
    capture=inspect(log,require_setup=True)
    expected=[json.loads(line) for line in (run/'native-events.jsonl').read_text().splitlines()]
    requests={row['context']:row for row in map(json.loads,(run/'request-map.jsonl').read_text().splitlines()) if row['kind']=='request'}
    observed=[];contexts={};batches=[];tid=None
    for line in log.read_text().splitlines():
        if line.startswith('MARKER_WRITE '):
            item=json.loads(line[len('MARKER_WRITE '):]);marker=item['marker']
            if item['size']!=item['result'] or item['tid']!=marker['tid']:
                raise ValueError('incomplete or mismatched marker write')
            observed.append(marker)
            if marker['kind'] in CONTEXT_KINDS:contexts[item['tid']]=marker['request']
        elif line.startswith('SUBMITTER '):
            tid=int(re.fullmatch(r'SUBMITTER pid=\d+ tid=(\d+)',line)[1])
        elif line.startswith('BATCH '):
            context=contexts.get(tid)
            if context not in (None,0) and context not in requests:
                raise ValueError('unknown submission context')
            batches.append(dict(batch=len(batches),tid=tid,execution_context=context,
                                rpc_id=requests[context]['rpc_id'] if context else None))
    if observed!=expected:raise ValueError('debugger marker sequence differs from native log')
    if len(batches)!=len(capture['batches']):raise ValueError('batch count mismatch')
    return dict(markers=len(observed),batches=batches,
                submission_context_counts=dict(Counter(str(b['execution_context']) for b in batches)),
                artifact_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [log,run/'native-events.jsonl',run/'request-map.jsonl']},
                limitations=['marker producers and controlled workload trusted; marker FD authority not independently validated',
                             'submission execution context is not per-SQE causal ownership',
                             'null context means no context marker observed for thread; zero means explicit unowned context'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('run',type=Path)
    print(json.dumps(report(p.parse_args().run),indent=2))
