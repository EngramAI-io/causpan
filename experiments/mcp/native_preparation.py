#!/usr/bin/env python3
"""Validate preparation-to-SQE identity and report execution context at preparation."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
from native_marker_timeline import report as marker_report, CONTEXT_KINDS


def report(run):
    markers=marker_report(run)
    pending={};contexts={};tid=None;ring=None;joined=[]
    for number,line in enumerate((run/'debugger.log').read_text().splitlines(),1):
        if line.startswith('MARKER_WRITE '):
            item=json.loads(line[13:]);m=item['marker']
            if m['kind'] in CONTEXT_KINDS:contexts[item['tid']]=m['request']
        elif line.startswith('PREPARER '):tid=int(line.split('=')[1])
        elif line.startswith('PREP '):
            values={k:int(v) for k,v in re.findall(r'(\w+)=(-?\d+)',line)}
            key=(values['ring_fd'],values['user_data'])
            if key in pending:raise ValueError('duplicate pending preparation')
            pending[key]=dict(values,line=number,tid=tid,context=contexts.get(tid))
        elif line.startswith('BATCH '):ring=int(re.search(r'fd=(\d+)',line)[1])
        elif line.startswith('SQE '):
            values={k:int(v) for k,v in re.findall(r'(\w+)=(-?\d+)',line)}
            prep=pending.pop((ring,values['user_data']),None)
            if prep is None:raise ValueError('missing preparation')
            if (prep['epoll_fd'],prep['target'],prep['control'])!=(values['fd'],values['target'],values['control']):
                raise ValueError('preparation/SQE mismatch')
            joined.append(dict(preparation=prep,sqe_line=number))
    if pending:raise ValueError('unsubmitted preparations')
    return dict(operations=len(joined),preparation_context_counts=dict(Counter(str(x['preparation']['context']) for x in joined)),
                joins=joined,artifact_sha256=markers['artifact_sha256'],
                limitations=['binary-specific breakpoint after SQE stores','preparation context is not inferred causal ownership',
                             'identity retired at observed SQE; completion validation supplied by native capture validator'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('run',type=Path)
    print(json.dumps(report(p.parse_args().run),indent=2))
