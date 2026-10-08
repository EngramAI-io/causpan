#!/usr/bin/env python3
"""Independent descriptor workload oracle; payload slots are never inference input."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re


def score(run):
    rows = [json.loads(line) for line in (run/'causal-attribution.jsonl').read_text().splitlines()]
    calls = [json.loads(line) for line in (run/'tool-calls.jsonl').read_text().splitlines()]
    slots = {c['arguments']['slot']: c['id'] for c in calls if c['tool'] == 'worker_slot'}
    observations = {}
    errors = []
    receiver_pids = set()
    for row in rows:
        rights = row.get('descriptor_rights')
        if rights is None:
            continue
        if not rights['decoded'] or not rights['succeeded'] or rights['control_truncated'] or len(rights['fds']) != 1:
            errors.append(dict(source=row['source'], error='incomplete or unsuccessful descriptor observation'))
            continue
        match = re.search(r'iov_base=("(?:\\.|[^"\\])*")', row['args'])
        if not match:
            errors.append(dict(source=row['source'], error='missing oracle payload'))
            continue
        message = json.loads(json.loads(match[1]))
        slot = message['slot']
        key = (slot, rights['direction'])
        if slot not in slots or key in observations:
            errors.append(dict(source=row['source'], error='unknown or repeated oracle slot/direction'))
        observations[key] = dict(event=row, message=message, fd=rights['fds'][0])
        if rights['direction'] == 'receive':
            receiver_pids.add(row['pid'])
        elif row['request_ids'] != [slots.get(slot)]:
            errors.append(dict(source=row['source'], error='send request attribution mismatch'))
    counts = Counter()
    target = str(run/'sandbox/slots.bin')
    for slot, request in slots.items():
        send = observations.get((slot, 'send'))
        receive = observations.get((slot, 'receive'))
        if not send or not receive:
            errors.append(dict(slot=slot, error='missing send/receive observation'))
            continue
        if send['message'] != receive['message'] or send['event']['pid'] == receive['event']['pid']:
            errors.append(dict(slot=slot, error='payload or process boundary mismatch'))
        effects = [r for r in rows if r['pid'] == receive['event']['pid'] and r['syscall'] in {'pwrite64','pread64'}
                   and r['paths'] == [target] and re.search(r',\s*'+str(slot*128)+r'\s*$', r['args'])]
        if Counter(r['syscall'] for r in effects) != {'pwrite64':1, 'pread64':1}:
            errors.append(dict(slot=slot, error='receiver effect count mismatch'))
        for effect in effects:
            if int(re.match(r'\d+', effect['args'])[0]) != receive['fd'] or effect['request_ids'] != [request]:
                errors.append(dict(source=effect['source'], error='received descriptor or request mismatch'))
            if receive['event']['completion_ns'] is None or effect['timestamp_ns'] < receive['event']['completion_ns']:
                errors.append(dict(source=effect['source'], error='effect preceded observed receive completion'))
        counts['transfers'] += 1
        counts['receiver_file_effects'] += len(effects)
    opens = [r for r in rows if r['pid'] in receiver_pids and r['syscall'] in {'open','openat','openat2'} and target in r['paths']]
    if opens:
        errors.append(dict(error='receiver independently opened target', sources=[r['source'] for r in opens]))
    graph_path = run/'provenance.jsonl'
    transfer_nodes = []
    if graph_path.exists():
        graph = [json.loads(line) for line in graph_path.read_text().splitlines()]
        transfer_nodes = [r for r in graph if r.get('kind') == 'descriptor_transfer' and r['type'] == 'node']
        expected_pairs = {(observations[(slot,'send')]['event']['source'], observations[(slot,'receive')]['event']['source'],
                           observations[(slot,'send')]['fd'], observations[(slot,'receive')]['fd'])
                          for slot in slots if (slot,'send') in observations and (slot,'receive') in observations}
        actual_pairs = [(r['send'],r['receive'],r['sender_fd'],r['receiver_fd']) for r in transfer_nodes]
        if len(actual_pairs) != len(expected_pairs) or set(actual_pairs) != expected_pairs:
            errors.append(dict(error='descriptor provenance pairs disagree with independent payload oracle'))
        counts['verified_provenance_pairs'] = len(actual_pairs)
    report = dict(valid=not errors, counts=dict(counts), receiver_pids=sorted(receiver_pids),
                  receiver_target_opens=len(opens), mismatches=errors,
                  oracle='controlled JSON payload slots and matching received FD numbers; used only for scoring',
                  transfer_provenance_pairing_evaluated=graph_path.exists())
    (run/'rights-score.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
    if errors:
        raise RuntimeError('descriptor transfer oracle disagrees')
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('run', type=Path)
    score(p.parse_args().run.resolve())
