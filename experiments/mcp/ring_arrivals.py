#!/usr/bin/env python3
"""Describe measured request overlap and ring batching, never infer from scheduling intent."""
import argparse
import collections
import hashlib
import json
from pathlib import Path


def report(run):
    manifest=json.loads((run/'manifest.json').read_text())
    causal=json.loads((run/'causal-report.json').read_text())
    score=json.loads((run/'ring-score.json').read_text())
    if manifest['status']!='complete' or not causal['valid'] or not score['valid']:
        raise ValueError('arrival report requires a complete validated ring capture')
    if manifest['scenario']!='uring-shared':raise ValueError('shared ring capture required')
    if set(causal.get('output_sha256',{}))!={'causal-attribution.jsonl','provenance.jsonl'}:
        raise ValueError('missing artifact identities')
    for name,digest in causal['output_sha256'].items():
        if hashlib.sha256((run/name).read_bytes()).hexdigest()!=digest:
            raise ValueError('artifact identity mismatch')
    protocol=[json.loads(line) for line in (run/'protocol.jsonl').read_text().splitlines()]
    starts={};ends={}
    for row in protocol:
        message=row['message']
        if row['direction']=='request' and message.get('method')=='tools/call' and message['params']['name']=='worker_slot':
            identity=message['id']
            if identity in starts:raise ValueError('duplicate request identity')
            starts[identity]=row['mono_ns']
        elif row['direction']=='response' and message.get('id') in starts:
            identity=message['id']
            if identity in ends:raise ValueError('duplicate response identity')
            ends[identity]=row['mono_ns']
    if not starts or set(starts)!=set(ends) or any(ends[k]<v for k,v in starts.items()):
        raise ValueError('incomplete or inverted request intervals')
    graph=[json.loads(line) for line in (run/'provenance.jsonl').read_text().splitlines()]
    batches=collections.defaultdict(list)
    for node in graph:
        if node['type']=='node' and node['kind']=='ring_operation':batches[node['batch']].append(node)
    ids=list(starts)
    overlap=sum(starts[a]<ends[b] and starts[b]<ends[a] for i,a in enumerate(ids) for b in ids[i+1:])
    points=sorted([(t,1) for t in starts.values()]+[(t,-1) for t in ends.values()])
    active=peak=0
    for _,change in points:active+=change;peak=max(peak,active)
    return dict(requests=len(starts),overlapping_pairs=overlap,peak_active_requests=peak,
                batches=[dict(batch=b,operations=len(ops),requests=len({r for op in ops for r in op['request_ids']})) for b,ops in sorted(batches.items())],
                evidence='protocol monotonic request/response intervals and validated ring graph',
                limitation='Observed overlap is not simultaneous kernel execution; idle flushing does not guarantee batch membership.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('run',type=Path)
    print(json.dumps(report(parser.parse_args().run),indent=2))
