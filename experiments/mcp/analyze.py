#!/usr/bin/env python3
"""Conservative syscall parsing and candidate-set attribution, with a separate path oracle."""
import argparse
import csv
from collections import Counter, defaultdict
from decimal import Decimal
import json
from pathlib import Path
import re

LINE = re.compile(r'^(\d+\.\d+)\s+(.*)$')
CALL = re.compile(r'^(\w+)\((.*)\)\s+=\s+(0x[0-9a-f]+|-?\d+|\?)(.*)$')
FD_OPS = {'read','write','readv','writev','pread64','pwrite64','close','fstat','fchmod','fchown','ftruncate','fsync','fdatasync','getdents64','fcntl','dup','dup2','dup3','recvfrom','recvmsg','sendto','sendmsg'}
PATH_OPS = {'openat','open','stat','lstat','newfstatat','statx','access','faccessat',
            'faccessat2','chmod','fchmodat','fchownat','mkdir','mkdirat','rmdir','link','linkat','symlink','symlinkat','utimensat','readlink','readlinkat','rename','renameat','renameat2','unlink','unlinkat'}
CLONE_FILES = 0x400      # Linux clone(2) flag: child shares parent's file descriptor table.
CLONE_THREAD = 0x10000   # Linux clone(2) flag: child is placed in same thread group (like pthread_create).
CLONE_FLAG_BITS = {
    'CLONE_FILES': CLONE_FILES,
    'CLONE_THREAD': CLONE_THREAD,
}

def clone_has_flag(args,flag):
    if flag in args:return True
    match=re.search(r'\bflags=(0x[0-9a-fA-F]+|[0-9]+)',args)
    return bool(match and int(match[1],0)&CLONE_FLAG_BITS[flag])

def parse_traces(directory):
    events, quality = [], Counter()
    for file in sorted(directory.glob('strace.*')):
        tid = int(file.suffix[1:])
        pending = None
        for line_no, raw in enumerate(file.read_text().splitlines(), 1):
            match = LINE.match(raw)
            if not match:
                quality['non_timestamp_lines'] += 1
                continue
            ts, body = match.groups()
            ns = int(Decimal(ts)*1_000_000_000)
            if '<unfinished ...>' in body:
                pending = (ns, body.split('<unfinished ...>')[0], line_no)
                quality['unfinished'] += 1
                continue
            if body.startswith('<... '):
                if pending is None:
                    quality['orphan_resumed'] += 1
                    continue
                ns, prefix, line_no = pending
                body = prefix + body.split(' resumed>',1)[1]
                pending = None
                quality['rejoined'] += 1
            if body.startswith(('+++', '---')) or re.match(r'exit(?:_group)?\(.*\)\s+=\s+\?', body):
                # A tracee may be terminated while blocked in a syscall (for
                # example, epoll_pwait during orderly process-group teardown).
                # strace then has no syscall-exit record to resume. Preserve
                # that fact separately from a genuinely truncated trace file.
                if pending and (body.startswith('+++ exited with') or body.startswith('+++ killed by')):
                    quality['terminal_interrupted'] += 1
                    pending = None
                quality['lifecycle_lines'] += 1
                continue
            m = CALL.match(body)
            if not m:
                quality['unparsed'] += 1
                continue
            name, args, ret, tail = m.groups()
            # Only path arguments and FD annotations, never paths embedded in read/write payloads.
            paths = []
            if name in FD_OPS:
                fd = re.match(r'\d+<((?:[A-Za-z0-9_-]+|\(null\)):\[.*?\]|[^>]+)>', args)
                if fd: paths.append(fd[1])
            elif name in PATH_OPS:
                paths = re.findall(r'"([^"\\]*)"', args)
            events.append(dict(timestamp_ns=ns, tid=tid, syscall=name, args=args,
                               return_value=None if ret=='?' else int(ret,16) if ret.startswith('0x') else int(ret),
                               completion='restart' if ret=='?' and 'ERESTART' in tail else 'unknown' if ret=='?' else 'returned',
                               paths=paths, source=f'{file.name}:{line_no}'))
        if pending: quality['incomplete_at_eof'] += 1
    events.sort(key=lambda e:e['timestamp_ns'])
    # Clone flags distinguish new threads from child processes, without querying dead /proc entries.
    parents = {}
    for e in events:
        if e['syscall'] in {'clone','clone3'} and (e['return_value'] or 0) > 0:
            parents[e['return_value']] = (e['tid'], clone_has_flag(e['args'],'CLONE_THREAD'))
    def tgid(tid):
        seen = set()
        while tid in parents and parents[tid][1] and tid not in seen:
            seen.add(tid)
            tid = parents[tid][0]
        return tid
    for e in events: e['pid'] = tgid(e['tid'])
    quality['parsed'] = len(events)
    return events, dict(quality)

def analyze(run):
    protocol = [json.loads(x) for x in (run/'protocol.jsonl').read_text().splitlines()]
    calls = {}
    seen_ids=set()
    for row in protocol:
        m = row['message']
        if row['direction']=='request' and 'method' in m and 'id' in m:
            if type(m['id']) not in (int,str) or m['id'] in seen_ids:
                raise ValueError('invalid or reused MCP request ID within one session')
            seen_ids.add(m['id'])
        if row['direction']=='request' and m.get('method')=='tools/call':
            calls[m['id']] = dict(id=m['id'], start_ns=row['wall_ns'], end_ns=None,
                                  tool=m['params']['name'], arguments=m['params'].get('arguments',{}))
        elif row['direction']=='response' and m.get('id') in calls:
            calls[m['id']]['end_ns'] = row['wall_ns']
            calls[m['id']]['error'] = 'error' in m or m.get('result',{}).get('isError',False)
    events, quality = parse_traces(run/'traces')
    # Unique resource ownership is a workload oracle only. Reused resources remain unlabelled.
    owners = defaultdict(set)
    for c in calls.values():
        for key in ['path','source','destination']:
            if key in c['arguments']: owners[c['arguments'][key]].add(c['id'])
        for path in c['arguments'].get('paths',[]): owners[path].add(c['id'])
    root = str(run/'sandbox')+'/'
    data = [e for e in events if any(p.startswith(root) for p in e['paths'])]
    # Server root determined by execve, not by oracle resources.
    roots = [e['pid'] for e in events if e['syscall']=='execve' and
             any(name in e['args'] for name in ['server-filesystem/dist/index.js','control-server.mjs','causpan-tokio-server']) and e['return_value']==0]
    if len(set(roots)) != 1: raise RuntimeError(f'cannot identify server PID: {roots}')
    pid = roots[0]
    counts = {s:Counter() for s in ['pid','request_window']}
    annotated = []
    for e in data:
        possible = set().union(*(owners.get(path,set()) for path in e['paths']))
        truth = next(iter(possible)) if len(possible)==1 else None
        candidates = {
            'pid':list(calls) if e['pid']==pid else [],
            'request_window':[c['id'] for c in calls.values() if e['pid']==pid and
                              c['end_ns'] is not None and c['start_ns'] <= e['timestamp_ns'] <= c['end_ns']]}
        for strategy, ids in candidates.items():
            n = counts[strategy]
            n['events'] += 1
            n['ambiguous' if len(ids)>1 else 'singleton' if ids else 'unattributed'] += 1
            if truth is not None:
                n['oracle_labelled'] += 1
                n['correct_singleton'] += int(ids==[truth])
                n['wrong_singleton'] += int(len(ids)==1 and ids[0]!=truth)
                n['truth_in_candidates'] += int(truth in ids)
        annotated.append(dict(**e, oracle_request_id=truth, candidates=candidates))
    def write_jsonl(name, rows):
        (run/name).write_text(''.join(json.dumps(x)+'\n' for x in rows))
    write_jsonl('kernel-events.jsonl',events)
    write_jsonl('tool-calls.jsonl',calls.values())
    write_jsonl('attribution.jsonl',annotated)
    with (run/'timeline.csv').open('w', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['timestamp_ns','pid','tid','syscall','paths','window_candidates','oracle_request_id','source'])
        for e in annotated:
            writer.writerow([e['timestamp_ns'],e['pid'],e['tid'],e['syscall'],json.dumps(e['paths']),
                             json.dumps(e['candidates']['request_window']),e['oracle_request_id'],e['source']])
    result = dict(tool_calls=len(calls), incomplete_calls=sum(c['end_ns'] is None for c in calls.values()),
                  tool_errors=sum(bool(c.get('error')) for c in calls.values()),
                  server_pid=pid, parser=quality, sandbox_events=len(data),
                  sandbox_tids=sorted({e['tid'] for e in data}),
                  sandbox_syscalls=dict(Counter(e['syscall'] for e in data)),
                  oracle_labelled=sum(e['oracle_request_id'] is not None for e in annotated),
                  baselines={k:dict(v) for k,v in counts.items()},
                  tid_baseline='Not scored: stdio request boundaries do not expose server execution TID.')
    (run/'report.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    if not calls or not data or result['incomplete_calls'] or result['tool_errors']:
        raise RuntimeError('experiment incomplete: missing calls/events, unfinished calls, or tool errors')
    return result

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('run',type=Path)
    analyze(p.parse_args().run.resolve())
