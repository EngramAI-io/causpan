#!/usr/bin/env python3
"""Resource-creation ancestry for native epoll operations; not execution ownership."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
from native_marker_timeline import report as marker_report, CONTEXT_KINDS
from native_socket_lifetimes import link_lines


def join(text):
    resources=link_lines(text,include_controls=True)
    contexts={};threads={};at_line={};batch=-1;batch_at_line={}
    for number,line in enumerate(text.splitlines(),1):
        if line.startswith('BATCH '):batch+=1
        if line.startswith('SQE '):batch_at_line[number]=batch
        if line.startswith('MARKER_WRITE '):
            item=json.loads(line[len('MARKER_WRITE '):]);marker=item['marker']
            if marker['kind'] in CONTEXT_KINDS:contexts[item['tid']]=marker['request']
        elif line.startswith('LIFECYCLE_THREAD '):
            thread,tid=map(int,re.fullmatch(r'LIFECYCLE_THREAD thread=(\d+) tid=(\d+)',line).groups())
            if thread in threads and threads[thread]!=tid:raise ValueError('thread identity changed')
            threads[thread]=tid
        else:
            match=re.match(r'(?:SOCKET_STOP|CONTROL_FD_STOP) thread=(\d+) ',line)
            if match:
                thread=int(match[1])
                if thread not in threads:raise ValueError('missing lifecycle thread identity')
                at_line[number]=contexts.get(threads[thread])
    installations={}
    for item in resources['installations']:
        entry=at_line[item['entry_line']];returned=at_line[item['return_line']]
        context=entry if entry==returned else None
        installations[item['id']]=dict(item,creation_context=context)
    references=[]
    for item in resources['references']:
        installation=installations.get(item['installation'])
        references.append(dict(item,batch=batch_at_line[item['line']],resource_creation_context=installation['creation_context'] if installation else None))
    return dict(installations=list(installations.values()),references=references,
                resource_context_counts=dict(Counter(str(r['resource_creation_context']) for r in references)))


def report(run):
    markers=marker_report(run)  # Validates complete ring capture and marker sequence first.
    result=join((run/'debugger.log').read_text())
    requests={row['context']:row['rpc_id'] for row in map(json.loads,(run/'request-map.jsonl').read_text().splitlines()) if row['kind']=='request'}
    for item in result['references']:
        context=item['resource_creation_context']
        if context not in (None,0) and context not in requests:raise ValueError('unknown creation context')
        item['resource_creation_rpc_id']=requests.get(context)
    return dict(**result,artifact_sha256=markers['artifact_sha256'],
                submission_context_counts=markers['submission_context_counts'],
                limitations=markers['limitations']+['resource creator is not necessarily operation owner',
                    'descriptor replacement outside observed creation/close syscalls remains unsupported',
                    'shared resources may serve several requests; this report preserves creation ancestry only'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('run',type=Path)
    print(json.dumps(report(p.parse_args().run),indent=2))
