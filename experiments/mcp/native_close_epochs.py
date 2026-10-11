#!/usr/bin/env python3
"""Partition observed epoll targets at successful closes; not OFD identity inference."""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import re
from inspect_native_windows import inspect


def report(path):
    validated=inspect(path,require_setup=True)
    pending={};epochs=collections.Counter();references=[];closes=[]
    for number,line in enumerate(path.read_text().splitlines(),1):
        match=re.fullmatch(r'CLOSE_STOP thread=(\d+) value=(-?\d+)',line)
        if match:
            thread,value=map(int,match.groups())
            if thread not in pending:pending[thread]=(value,number)
            else:
                fd,start=pending.pop(thread)
                closes.append(dict(fd=fd,result=value,entry_line=start,return_line=number))
                if value==0:epochs[fd]+=1
        elif line.startswith('SQE '):
            match=re.search(r' target=(\d+) control=(\d+)',line)
            if not match:raise ValueError('target metadata missing')
            fd,control=map(int,match.groups())
            references.append(dict(target_fd=fd,close_epoch=epochs[fd],control=control,line=number,
                unresolved_close=any(fd==value[0] for value in pending.values())))
    if pending:raise ValueError('unpaired close observations')
    groups=collections.defaultdict(set)
    for reference in references:groups[reference['target_fd']].add(reference['close_epoch'])
    return dict(valid=True,operations=validated['operations'],references=references,closes=closes,
        targets_crossing_successful_closes={str(fd):sorted(values) for fd,values in groups.items() if len(values)>1},
        log_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        limitations=['single process shared descriptor table assumed','epochs count observed successful closes only','creation, dup, transfer, close_range and failed-close effects untracked','epochs are not stable resource identities or request owners'])

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('log',type=Path)
    print(json.dumps(report(parser.parse_args().log),indent=2))
