#!/usr/bin/env python3
"""Scoped observed socket installation links; not general descriptor/OFD tracking."""
import argparse
import hashlib
import json
from pathlib import Path
import re
from inspect_native_windows import inspect


def link_lines(text, include_controls=False):
    pending={};active={};references=[];installations=[];last_close_start={}
    for number,line in enumerate(text.splitlines(),1):
        match=re.fullmatch(r'(?:SOCKET_STOP|CONTROL_FD_STOP) thread=(\d+) syscall=(\d+) value=(-?\d+)',line)
        close=re.fullmatch(r'CLOSE_STOP thread=(\d+) value=(-?\d+)',line)
        if match and (include_controls or line.startswith('SOCKET_STOP')):
            thread,syscall,value=map(int,match.groups());key=('install',thread,syscall)
            if key not in pending:pending[key]=(value,number)
            else:
                _,start=pending.pop(key)
                if value>=0:
                    kind={198:'socket',242:'socket',19:'eventfd',20:'epoll'}.get(syscall)
                    if kind is None:raise ValueError('unsupported installation syscall')
                    installation=dict(id=f'{kind}-install:{number}',kind=kind,fd=value,syscall=syscall,entry_line=start,return_line=number)
                    if last_close_start.get(value,0)>=start or any(key[0]=='close' and state[0]==value for key,state in pending.items()):
                        installation['projection_rejected']='overlapping_close'
                        active.pop(value,None)
                    else:active[value]=installation
                    installations.append(installation)
        elif close:
            thread,value=map(int,close.groups());key=('close',thread)
            if key not in pending:
                pending[key]=(value,number)
                last_close_start[value]=number
                # Any observed close attempt invalidates the projection, including
                # unresolved or failed returns; retaining stale identity is unsafe.
                active.pop(value,None)
            else:pending.pop(key)
        elif line.startswith('SQE '):
            target=re.search(r' target=(\d+) ',line)
            if not target:raise ValueError('missing target descriptor')
            fd=int(target[1]);installation=active.get(fd)
            references.append(dict(line=number,target_fd=fd,installation=installation['id'] if installation else None,
                                   status=f'observed_{installation["kind"]}_installation' if installation else 'unresolved'))
    if pending:raise ValueError('incomplete lifecycle observations')
    return dict(installations=installations,references=references,
                linked=sum(r['installation'] is not None for r in references),unresolved=sum(r['installation'] is None for r in references))


def report(path, include_controls=False):
    capture=inspect(path,require_setup=True);result=link_lines(path.read_text(), include_controls=include_controls)
    if len(result['references'])!=capture['operations']:raise ValueError('operation/reference count mismatch')
    return dict(**result,log_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                scope='Observed socket/accept4 and optional eventfd/epoll installations within the controlled single-process workload',
                limitations=['uncaptured replacement mechanisms can invalidate links','shared descriptor table assumed','not general OFD identity','no request ownership inferred'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('log',type=Path)
    print(json.dumps(report(p.parse_args().log),indent=2))
