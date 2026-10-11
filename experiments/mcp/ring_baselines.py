#!/usr/bin/env python3
"""Conditional ownership baselines given the adapter's ring-operation inventory.

These baselines do not detect ring operations from syscalls. They are deliberately
provided the known operation inventory and associated enter event for comparison.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path


def evaluate(calls,operations,events):
    by_source={e['source']:e for e in events}
    truth={c['arguments']['slot']*512+i*128:c['id'] for c in calls for i in range(3)}
    results={name:Counter() for name in ['pid_lifetime','request_window_at_enter']}
    histograms={name:Counter() for name in results}
    for op in operations:
        expected=truth[op['offset']]
        enter=by_source[op['syscall_evidence']]
        candidates={
            'pid_lifetime':{c['id'] for c in calls},
            'request_window_at_enter':{c['id'] for c in calls if c['start_ns']<=enter['timestamp_ns']<=c['end_ns']},
        }
        for name,owners in candidates.items():
            counts=results[name];counts['operations']+=1;histograms[name][len(owners)]+=1
            counts['covered']+=expected in owners
            counts['exact_correct']+=owners=={expected}
            counts['extra_candidate_edges']+=len(owners-{expected})
            counts['ambiguous' if len(owners)>1 else 'singleton' if owners else 'unattributed']+=1
    return {name:{'counts':dict(results[name]),'candidate_count_histogram':dict(histograms[name])} for name in results}


def inspect(run):
    manifest=json.loads((run/'manifest.json').read_text())
    if manifest.get('scenario')!='uring-shared' or manifest.get('status')!='complete':
        raise ValueError('requires a completed shared-ring run')
    report=json.loads((run/'causal-report.json').read_text())
    if not report['valid'] or not json.loads((run/'ring-score.json').read_text())['valid']:
        raise ValueError('attribution or independent oracle invalid')
    if set(report.get('output_sha256',{}))!={'causal-attribution.jsonl','provenance.jsonl'}:
        raise ValueError('missing output integrity hashes')
    for name,digest in report['output_sha256'].items():
        if hashlib.sha256((run/name).read_bytes()).hexdigest()!=digest:raise ValueError('output digest mismatch')
    events=[json.loads(x) for x in (run/'causal-attribution.jsonl').read_text().splitlines()]
    graph=[json.loads(x) for x in (run/'provenance.jsonl').read_text().splitlines()]
    operations=[r for r in graph if r['type']=='node' and r['kind']=='ring_operation']
    if len({o['runtime_pid'] for o in operations})!=1:raise ValueError('baseline requires one shared worker')
    calls=[json.loads(x) for x in (run/'tool-calls.jsonl').read_text().splitlines()]
    calls=[c for c in calls if c['tool']=='worker_slot']
    result=dict(scope='conditional ownership given enumerated ring operations and their enter syscall; not operation detection',
                source_run=str(run),baselines=evaluate(calls,operations,events),
                scorer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    (run/'ring-baselines.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('run',type=Path)
    print(json.dumps(inspect(parser.parse_args().run.resolve()),indent=2))
