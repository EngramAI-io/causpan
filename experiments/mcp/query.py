#!/usr/bin/env python3
"""Inspect bindings and the evidence chain behind a request or individual syscall."""
import argparse
import json
import hashlib
from pathlib import Path


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('run',type=Path)
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument('--request',help='JSON request ID: 3 or a quoted JSON string')
    group.add_argument('--event',help='Raw trace source, e.g. strace.123:42')
    p.add_argument('--fixture-only',action='store_true')
    args=p.parse_args();run=args.run.resolve()
    manifest=json.loads((run/'manifest.json').read_text())
    if manifest.get('status')!='complete':raise SystemExit('Run did not complete validation; inspect raw artifacts and reports instead')
    for name in ['control-score.json','batch-score.json','fileops-score.json','network-score.json']:
        if (run/name).exists() and not json.loads((run/name).read_text())['valid']:
            raise SystemExit('Independent evaluation failed: '+name)
    report=json.loads((run/'causal-report.json').read_text())
    if not report['valid']:raise SystemExit('Capture invalid: '+ '; '.join(report['errors']))
    for name,digest in report.get('output_sha256',{}).items():
        if hashlib.sha256((run/name).read_bytes()).hexdigest()!=digest:raise SystemExit('Attribution output integrity mismatch: '+name)
    request=json.loads(args.request) if args.request is not None else None
    selected=[]
    for row in map(json.loads,(run/'causal-attribution.jsonl').read_text().splitlines()):
        if args.event and row['source']!=args.event:continue
        if args.request is not None and request not in row.get('request_ids',[row['request_id']]):continue
        if args.fixture_only and not any(path.startswith(str(run/'sandbox')+'/') for path in row['paths']):continue
        selected.append(row)
    graph=list(map(json.loads,(run/'provenance.jsonl').read_text().splitlines()))
    wanted={r['id'] for r in graph if r['type']=='node' and r['kind']=='syscall' and any(r['id'].endswith('syscall:'+e['source']) for e in selected)}
    ancestors=set(wanted)
    changed=True
    while changed:
        changed=False
        for edge in graph:
            if edge['type']=='edge' and edge['kind'] in {'submitted','executed','spawned','joined','created_task','polled'} and edge['target'] in ancestors and edge['source'] not in ancestors:
                ancestors.add(edge['source']);changed=True
    evidence=[r for r in graph if (r['type']=='node' and r['id'] in ancestors) or
              (r['type']=='edge' and r['kind'] in {'submitted','executed','spawned','joined','created_task','polled'} and r['source'] in ancestors and r['target'] in ancestors)]
    if json.loads((run/'causal-report.json').read_text())!=report:raise SystemExit('Analysis changed while reading; retry after it completes')
    print(json.dumps({'events':selected,'provenance':evidence},indent=2))

if __name__=='__main__':main()
