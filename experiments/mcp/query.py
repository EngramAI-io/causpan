#!/usr/bin/env python3
"""Inspect bindings and the evidence chain behind a request or individual syscall."""
import argparse
import json
import hashlib
from pathlib import Path


def select_row(row, request=None, event=None, fixture_root=None):
    if event is not None and row['source']!=event:return False
    if request is not None and request not in row.get('request_ids',[row.get('request_id')]) and request not in row.get('candidate_request_ids',[]):return False
    if fixture_root is not None and not any(path.startswith(str(fixture_root)+'/') for path in row['paths']):return False
    return True


def evidence_chain(graph,selected,request=None):
    wanted={r['id'] for r in graph if r['type']=='node' and r['kind']=='syscall' and any(r['id'].endswith('syscall:'+e['source']) for e in selected)}
    # Request queries retain handoff outcomes even when no syscall was executed.
    if request is not None:
        descendants={r['id'] for r in graph if r['type']=='node' and r['kind']=='mcp_request' and r.get('rpc_id')==request}
        changed=True
        while changed:
            changed=False
            for edge in graph:
                if edge['type']=='edge' and edge['kind'] in {'joined','ipc_sent','cancelled_before_execution'} and edge['source'] in descendants and edge['target'] not in descendants:
                    descendants.add(edge['target']);changed=True
        wanted.update(descendants)
    ancestors=set(wanted)
    changed=True
    while changed:
        changed=False
        for edge in graph:
            causal=edge['kind'] in {'cancelled_before_execution','ipc_sent','submitted','executed','spawned','joined','created_task','polled','connected','socket_effect','accepted','accepted_connection'}
            if edge['type']=='edge' and causal and edge['target'] in ancestors and edge['source'] not in ancestors:
                ancestors.add(edge['source']);changed=True
    evidence=[r for r in graph if (r['type']=='node' and r['id'] in ancestors) or
              (r['type']=='edge' and r['kind'] in {'cancelled_before_execution','ipc_sent','submitted','executed','spawned','joined','created_task','polled','connected','socket_effect','accepted','accepted_connection'} and r['source'] in ancestors and r['target'] in ancestors)]
    return evidence


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('run',type=Path)
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument('--request',help='JSON request ID: 3 or a quoted JSON string')
    group.add_argument('--event',help='Raw trace source, e.g. strace.123:42')
    p.add_argument('--fixture-only',action='store_true')
    p.add_argument('--allow-failed-workload',action='store_true',help='Inspect a failed workload only when attribution integrity remains valid; failed independent evaluations are still rejected')
    args=p.parse_args();run=args.run.resolve()
    manifest=json.loads((run/'manifest.json').read_text())
    if manifest.get('status')!='complete' and not (args.allow_failed_workload and manifest.get('status')=='failed'):
        raise SystemExit('Run did not complete validation; use --allow-failed-workload only for a failed workload with valid attribution')
    for name in ['control-score.json','batch-score.json','fileops-score.json','network-score.json']:
        if (run/name).exists() and not json.loads((run/name).read_text())['valid']:
            raise SystemExit('Independent evaluation failed: '+name)
    report=json.loads((run/'causal-report.json').read_text())
    if not report['valid']:raise SystemExit('Capture invalid: '+ '; '.join(report['errors']))
    if set(report.get('output_sha256',{}))!={'causal-attribution.jsonl','provenance.jsonl'}:
        raise SystemExit('Missing attribution output integrity hashes')
    for name,digest in report['output_sha256'].items():
        if hashlib.sha256((run/name).read_bytes()).hexdigest()!=digest:raise SystemExit('Attribution output integrity mismatch: '+name)
    request=json.loads(args.request) if args.request is not None else None
    selected=[]
    for row in map(json.loads,(run/'causal-attribution.jsonl').read_text().splitlines()):
        if select_row(row,request=request,event=args.event,fixture_root=run/'sandbox' if args.fixture_only else None):selected.append(row)
    graph=list(map(json.loads,(run/'provenance.jsonl').read_text().splitlines()))
    evidence=evidence_chain(graph,selected,request=request)
    if json.loads((run/'causal-report.json').read_text())!=report:raise SystemExit('Analysis changed while reading; retry after it completes')
    print(json.dumps({'workload_status':manifest['status'],'workload_error':manifest.get('error'),
                      'attribution_valid':True,'events':selected,'provenance':evidence},indent=2))

if __name__=='__main__':main()
