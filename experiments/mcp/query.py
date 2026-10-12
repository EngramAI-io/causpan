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


def validate_snapshot_files(run,graph):
    for node in graph:
        if node['type']!='node' or node['kind']!='ring_snapshot':continue
        path=Path(node['path'])
        if path.parent.parent!=run or not path.parent.name.startswith('ring-memory-'):
            raise ValueError('snapshot path outside capture')
        if path.is_symlink() or path.parent.is_symlink():raise ValueError('snapshot symlink unsupported')
        try:digest=hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as error:raise ValueError('snapshot unavailable: '+str(path)) from error
        if digest!=node['sha256']:raise ValueError('snapshot integrity mismatch: '+str(path))


_NATIVE_EDGE_KINDS = {'prepared_as', 'observed_queue_episode', 'poll_prepared',
                      'observed_update_while_queued', 'canceled_before_poll',
                      'triggered_retry'}
_CAUSAL_EDGE_KINDS = {'ring_memory_observed', 'ring_snapshot_written',
                      'ring_resource_observed', 'ring_submitted',
                      'ring_submission_observed', 'ring_completion_observed',
                      'descriptor_sent', 'descriptor_received',
                      'cancelled_before_execution', 'ipc_sent', 'submitted',
                      'executed', 'spawned', 'joined', 'created_task',
                      'polled', 'connected', 'socket_effect', 'accepted',
                      'accepted_connection'} | _NATIVE_EDGE_KINDS
_HANDOFF_EDGE_KINDS = {'ring_submitted', 'ring_submission_observed',
                       'ring_completion_observed', 'descriptor_sent',
                       'descriptor_received'} | _NATIVE_EDGE_KINDS


def evidence_chain(graph,selected,request=None,operations=None):
    wanted={r['id'] for r in graph if r['type']=='node' and r['kind']=='syscall' and any(r['id'].endswith('syscall:'+e['source']) for e in selected)}
    wanted.update(r['id'] for r in (operations or []))
    # Request queries retain handoff outcomes even when no syscall was executed.
    if request is not None:
        descendants={r['id'] for r in graph if r['type']=='node'
                     and r.get('kind') in ('mcp_request', 'request')
                     and r.get('rpc_id')==request}
        changed=True
        while changed:
            changed=False
            for edge in graph:
                if edge['type']=='edge' and edge['kind'] in {'joined','ipc_sent','cancelled_before_execution'} and edge['source'] in descendants and edge['target'] not in descendants:
                    descendants.add(edge['target']);changed=True
        wanted.update(descendants)
    # Include descriptor handoffs caused by selected sends, without treating
    # the receiving dispatcher as executing under the sender's request.
    changed=True
    while changed:
        changed=False
        for edge in graph:
            if edge['type']=='edge' and edge['kind'] in _HANDOFF_EDGE_KINDS and edge['source'] in wanted and edge['target'] not in wanted:
                wanted.add(edge['target']);changed=True
    ancestors=set(wanted)
    changed=True
    while changed:
        changed=False
        for edge in graph:
            if edge['type']=='edge' and edge['kind'] in _CAUSAL_EDGE_KINDS and edge['target'] in ancestors and edge['source'] not in ancestors:
                ancestors.add(edge['source']);changed=True
    evidence=[r for r in graph if (r['type']=='node' and r['id'] in ancestors) or
              (r['type']=='edge' and r['kind'] in _CAUSAL_EDGE_KINDS and r['source'] in ancestors and r['target'] in ancestors)]
    return evidence


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('run',type=Path)
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument('--request',help='JSON request ID: 3 or a quoted JSON string')
    group.add_argument('--operation',help='Full ring_operation node ID from provenance output')
    group.add_argument('--event',help='Raw trace source, e.g. strace.123:42')
    p.add_argument('--fixture-only',action='store_true')
    p.add_argument('--allow-failed-workload',action='store_true',help='Inspect a failed workload only when attribution integrity remains valid; failed independent evaluations are still rejected')
    args=p.parse_args();run=args.run.resolve()
    manifest=json.loads((run/'manifest.json').read_text())
    if manifest.get('status')!='complete' and not (args.allow_failed_workload and manifest.get('status')=='failed'):
        raise SystemExit('Run did not complete validation; use --allow-failed-workload only for a failed workload with valid attribution')
    if manifest.get('scenario') == 'worker-rights':
        for required in ['control-score.json', 'rights-score.json']:
            if not (run/required).is_file():
                raise SystemExit('Missing required independent evaluation: '+required)
    if manifest.get('scenario') in {'uring','uring-memory','uring-reuse','uring-shared'} and not (run/'ring-score.json').is_file():
        raise SystemExit('Missing required independent evaluation: ring-score.json')
    for name in ['ring-score.json','control-score.json','batch-score.json','fileops-score.json','network-score.json','rights-score.json']:
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
        if args.operation is None and select_row(row,request=request,event=args.event,fixture_root=run/'sandbox' if args.fixture_only else None):selected.append(row)
    graph=list(map(json.loads,(run/'provenance.jsonl').read_text().splitlines()))
    try:validate_snapshot_files(run,graph)
    except ValueError as error:raise SystemExit(str(error)) from error
    operations=[]; omitted=0
    for node in graph:
        if node['type']!='node' or node['kind']!='ring_operation':continue
        if args.operation is not None and node['id']!=args.operation:continue
        if request is not None and request not in node.get('request_ids',[]):continue
        if args.event is not None and args.event not in [node.get('syscall_evidence'),node.get('submit_evidence'),node.get('completion_evidence')]:continue
        if args.fixture_only and not any(path.startswith(str(run/'sandbox')+'/') for path in node.get('paths',[])):
            omitted+=1;continue
        operations.append(node)
    if args.operation is not None and not operations and not omitted:
        raise SystemExit('Unknown ring operation ID')
    evidence=evidence_chain(graph,selected,request=request,operations=operations)
    if json.loads((run/'causal-report.json').read_text())!=report:raise SystemExit('Analysis changed while reading; use --allow-failed-workload only for a failed workload with valid attribution')
    print(json.dumps({'workload_status':manifest['status'],'workload_error':manifest.get('error'),
                      'attribution_valid':True,'events':selected,'ring_operations':operations,
                      'ring_operations_omitted_by_fixture_filter':omitted,'provenance':evidence},indent=2))

if __name__=='__main__':main()
