#!/usr/bin/env python3
"""Report context at observed uv__io_start watcher insertions."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
from native_marker_timeline import report as marker_report, CONTEXT_KINDS


def report(run):
    validated=marker_report(run);contexts={};tid=None;events=[]
    for number,line in enumerate((run/'debugger.log').read_text().splitlines(),1):
        if line.startswith('MARKER_WRITE '):
            item=json.loads(line[13:]);marker=item['marker']
            if marker['kind'] in CONTEXT_KINDS:contexts[item['tid']]=marker['request']
        elif line.startswith('WATCHER_THREAD '):tid=int(line.split('=')[1])
        elif line.startswith('WATCHER_ENQUEUE '):
            if tid is None:raise ValueError('watcher thread missing')
            values={k:int(v) for k,v in re.findall(r'(\w+)=(-?\d+)',line)}
            if set(values)!={'loop','watcher','fd','pevents','events'}:raise ValueError('malformed watcher record')
            events.append(dict(line=number,tid=tid,context=contexts.get(tid),**values))
    return dict(enqueue_context_counts=dict(Counter(str(x['context']) for x in events)),enqueue_events=events,
                artifact_sha256=validated['artifact_sha256'],limitations=['only uv__io_start insertion site observed',
                    'no watcher-to-SQE causal join yet','uv__io_stop and queue coalescing not covered'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('run',type=Path)
    print(json.dumps(report(p.parse_args().run),indent=2))
