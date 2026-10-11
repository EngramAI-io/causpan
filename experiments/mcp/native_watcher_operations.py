#!/usr/bin/env python3
"""Observed watcher queue ancestry to specific SQEs; coalescing remains unproven."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
from native_watcher_queue import report as queue_report
from native_preparation import report as preparation_report


def report(run):
    queues=queue_report(run);preparations=preparation_report(run)
    episodes={x['removal']['line']:x for x in queues['matches']}
    sqes={x['preparation']['line']:x['sqe_line'] for x in preparations['joins']}
    tid=None;prep_tid=None;removed={};calls={};links=[]
    for number,line in enumerate((run/'debugger.log').read_text().splitlines(),1):
        values={k:int(v) for k,v in re.findall(r'(\w+)=(-?\d+)',line)}
        if line.startswith('WATCHER_THREAD '):tid=values['tid']
        elif line.startswith('PREPARER '):prep_tid=values['tid']
        elif line.startswith('WATCHER_DEQUEUE '):removed[tid]=(number,values)
        elif line.startswith('WATCHER_CALL '):
            removal=removed.pop(tid,None)
            if removal is None:raise ValueError('preparation call without removal')
            n,event=removal
            if event['loop']!=values['loop'] or event['fd']!=values['target']:
                raise ValueError('watcher call identity mismatch')
            if tid in calls:raise ValueError('unconsumed watcher call')
            calls[tid]=(number,values,episodes.get(n))
        elif line.startswith('PREP '):
            call=calls.pop(prep_tid,None)
            if call is None:continue  # E.g. epoll ADD retry from flush.
            call_line,event,episode=call
            if any(event[k]!=values[k] for k in ['ring_fd','target','control']):
                raise ValueError('watcher call/preparation mismatch')
            links.append(dict(call_line=call_line,preparation_line=number,sqe_line=sqes[number],
                              target_fd=values['target'],queue_episode=episode,
                              enqueue_context=episode['insertion']['context'] if episode else None))
    if calls:raise ValueError('watcher call without preparation')
    return dict(links=links,operations=preparations['operations'],
                enqueue_context_counts=dict(Counter(str(x['enqueue_context']) for x in links)),
                artifact_sha256=queues['artifact_sha256'],limitations=queues['limitations']+[
                    'queue insertion ancestry is not exclusive ownership of coalesced watcher updates',
                    'preparations outside poll call site remain without watcher ancestry'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('run',type=Path)
    print(json.dumps(report(p.parse_args().run),indent=2))
