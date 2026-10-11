#!/usr/bin/env python3
"""Match observed watcher insertion/removal episodes without claiming SQE ownership."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
from native_marker_timeline import report as marker_report, CONTEXT_KINDS


def join(text):
    contexts={};tid=None;pending={};matches=[];unmatched=[];updates={};outside_updates=[];canceled=[];idle_stops=[]
    for number,line in enumerate(text.splitlines(),1):
        if line.startswith('MARKER_WRITE '):
            item=json.loads(line[13:]);m=item['marker']
            if m['kind'] in CONTEXT_KINDS:contexts[item['tid']]=m['request']
        elif line.startswith('WATCHER_THREAD '):tid=int(line.split('=')[1])
        elif line.startswith(('WATCHER_ENQUEUE ','WATCHER_DEQUEUE ','WATCHER_UPDATE ','WATCHER_CANCEL ')):
            values={k:int(v) for k,v in re.findall(r'(\w+)=(-?\d+)',line)}
            if set(values)!={'loop','watcher','fd','pevents','events'} or tid is None:
                raise ValueError('malformed queue observation')
            key=(values['loop'],values['watcher'])
            item=dict(values,line=number,tid=tid,context=contexts.get(tid))
            if line.startswith('WATCHER_CANCEL '):
                previous=pending.pop(key,None)
                episode_updates=updates.pop(key,[])
                if previous is None:idle_stops.append(item)
                elif previous['fd']!=item['fd']:unmatched.append(dict(reason='cancel_descriptor_changed',event=item,insertion=previous))
                else:canceled.append(dict(insertion=previous,cancellation=item,observed_updates=episode_updates))
                continue
            if line.startswith('WATCHER_UPDATE '):
                if key in pending:updates.setdefault(key,[]).append(item)
                else:outside_updates.append(item)
                continue
            if line.startswith('WATCHER_ENQUEUE '):
                if key in pending:
                    unmatched.append(dict(reason='replacement_without_observed_removal',event=pending.pop(key)))
                pending[key]=item
                updates[key]=[]
            else:
                previous=pending.pop(key,None)
                episode_updates=updates.pop(key,[])
                if previous is None:unmatched.append(dict(reason='no_observed_insertion',event=item))
                elif previous['fd']!=item['fd']:
                    unmatched.append(dict(reason='descriptor_changed',event=item,insertion=previous))
                else:matches.append(dict(insertion=previous,removal=item,observed_updates=episode_updates,masks_unchanged=all(previous[k]==item[k] for k in ['pevents','events'])))
    unmatched.extend(dict(reason='no_observed_removal',event=x) for x in pending.values())
    return dict(matches=matches,unmatched=unmatched,canceled=canceled,stops_without_pending_insertion=idle_stops,updates_outside_observed_episode=outside_updates,
                insertion_context_counts=dict(Counter(str(x['insertion']['context']) for x in matches)),
                removal_context_counts=dict(Counter(str(x['removal']['context']) for x in matches)))


def report(run):
    validated=marker_report(run)
    return dict(**join((run/'debugger.log').read_text()),artifact_sha256=validated['artifact_sha256'],
                limitations=['only observed start insertion and poll removal sites',
                             'stop/close lifecycle and intermediate coalescing not captured',
                             'matching pointer and FD is scoped queue evidence, not general lifetime proof or SQE ownership'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('run',type=Path)
    print(json.dumps(report(p.parse_args().run),indent=2))
