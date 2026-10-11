#!/usr/bin/env python3
"""Join observed ADD/EEXIST retry calls to original SQEs and watcher ancestry."""
import argparse
import json
from pathlib import Path
import re
from native_preparation import report as preparation_report
from native_watcher_operations import report as watcher_report


def report(run):
    prep=preparation_report(run);watchers=watcher_report(run)
    prep_to_sqe={x['preparation']['line']:x['sqe_line'] for x in prep['joins']}
    ancestry={x['sqe_line']:x for x in watchers['links']}
    operations={};errors={};calls={};tid=None;prep_tid=None;ring=None;links=[]
    for number,line in enumerate((run/'debugger.log').read_text().splitlines(),1):
        v={k:int(x) for k,x in re.findall(r'(\w+)=(-?\d+)',line)}
        if line.startswith('BATCH '):ring=v['fd']
        elif line.startswith('SQE '):operations[(ring,v['user_data'])]=dict(v,line=number)
        elif line.startswith('CQE '):operations[(ring,v['user_data'])]['result']=v['result']
        elif line.startswith('RETRY_THREAD '):tid=v['tid']
        elif line.startswith('PREPARER '):prep_tid=v['tid']
        elif line.startswith('ERROR_COMPLETION '):
            source=operations.get((v['ring_fd'],v['user_data']))
            if source is None or source.get('result')!=v['result']:raise ValueError('unobserved error completion')
            errors[tid]=(v,source)
        elif line.startswith('RETRY_CALL '):
            error=errors.pop(tid,None)
            if error is None:raise ValueError('retry without error')
            event,source=error
            if event['result']!=-17 or source['control']!=1 or v['control']!=3 or source['target']!=v['target'] or event['ring_fd']!=v['ring_fd']:
                raise ValueError('unsupported retry transition')
            if tid in calls:raise ValueError('duplicate retry call')
            calls[tid]=(number,v,source)
        elif line.startswith('PREP ') and prep_tid in calls:
            call_line,call,source=calls.pop(prep_tid)
            if any(call[k]!=v[k] for k in ['ring_fd','target','control']):raise ValueError('retry preparation mismatch')
            parent=ancestry.get(source['line'])
            links.append(dict(source_sqe_line=source['line'],retry_call_line=call_line,
                              retry_sqe_line=prep_to_sqe[number],target_fd=v['target'],
                              enqueue_context=parent['enqueue_context'] if parent else None))
    if calls:raise ValueError('unprepared retry')
    return dict(retries=links,artifact_sha256=prep['artifact_sha256'],limitations=[
        'only pinned ADD/EEXIST-to-MOD retry path','inherits queue insertion ancestry, not exclusive ownership',
        'other nonzero completions do not acquire retry edges'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('run',type=Path)
    print(json.dumps(report(p.parse_args().run),indent=2))
