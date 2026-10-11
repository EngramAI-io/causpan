#!/usr/bin/env python3
"""Validate serialized native debugger batches with changing queue positions."""
from collections import Counter
import argparse
import hashlib
import json
from pathlib import Path
import re


def validate_setups(text):
    blocks=re.split(r'SETUP_STOP tid=(\d+) x0=(-?\d+) params=(0x[0-9a-f]+)\n',text)
    pending={};setups={}
    positions=[m.start() for m in re.finditer(r'SETUP_STOP tid=',text)]
    for i in range(1,len(blocks),4):
        tid,value,address,body=blocks[i:i+4];words=[]
        for line in body.splitlines():
            if not re.match(r'^0x[0-9a-f]+:\s+0x[0-9a-f]{8}',line):break
            words.extend(int(x,16) for x in re.findall(r'0x([0-9a-f]{8})(?=\s|$)',line.split(':',1)[1]))
        if len(words)!=30:raise ValueError('truncated setup parameters')
        if tid not in pending:pending[tid]=(address,int(value))
        else:
            previous,entries=pending.pop(tid)
            if previous!=address:raise ValueError('setup entry/return address mismatch')
            fd=int(value)
            if fd<0:continue
            if fd in setups:raise ValueError('ring FD reuse unsupported')
            if entries!=256 or words[0]!=256 or words[1]!=512 or words[2]!=0 or words[16]!=8256:
                raise ValueError('unsupported kernel ring layout')
            if words[10:13]!=[0,4,16] or words[20:23]!=[8,12,20] or words[25]!=64:
                raise ValueError('unsupported ring counter or CQ offset')
            setups[fd]=dict(sq_entries=words[0],cq_entries=words[1],sq_array=words[16],observed_at=positions[(i-1)//4])
    if pending or not setups:raise ValueError('incomplete ring setup capture')
    return setups


def inspect(path,require_setup=False):
    text=path.read_text();batch=None;result=[];last_tail={};submitter=None
    if 'exited normally' not in text or 'Error in sourced' in text:raise ValueError('incomplete debugger run')
    setups=validate_setups(text) if require_setup else None
    position=0
    for raw_line in text.splitlines(keepends=True):
        line=raw_line.rstrip("\r\n");line_position=position;position+=len(raw_line)
        if line.startswith('SUBMITTER '):
            pid,tid=map(int,re.findall(r'=(\d+)',line));submitter=dict(pid=pid,tid=tid)
        elif line.startswith('BATCH fd='):
            if batch is not None:raise ValueError('interleaved batches unsupported')
            fd,head,tail,mask=map(int,re.findall(r'=(\d+)',line));count=(tail-head)&0xffffffff
            if mask!=255 or not 0<count<=mask+1:raise ValueError('invalid SQ window')
            if setups is not None and fd not in setups:raise ValueError('batch ring has no setup evidence')
            if setups is not None and setups[fd]['observed_at']>=line_position:raise ValueError('ring setup follows batch')
            if fd in last_tail and head!=last_tail[fd]:raise ValueError('gap or overlap between observed ring batches')
            batch=dict(fd=fd,head=head,tail=tail,count=count,sq={},cq={},submitter=submitter)
            submitter=None
        elif line.startswith('SQE '):
            if batch is None or 'returned' in batch:raise ValueError('SQE outside submission phase')
            values=list(map(int,re.findall(r'=(-?\d+)',line)))
            if len(values) not in {4,6,7}:raise ValueError('unsupported SQE record')
            index,opcode,fd,uid=values[:4]
            if not 0<=index<=255 or uid in batch['sq']:raise ValueError('invalid SQ index or duplicate identity')
            batch['sq'][uid]=dict(index=index,opcode=opcode,fd=fd,user_data=uid)
            if len(values)>=6:
                if opcode!=29 or values[4]>2147483647 or values[5] not in {1,2,3}:raise ValueError('unsupported epoll control semantics')
                batch['sq'][uid].update(target_fd=values[4],control_operation=values[5])
            if len(values)==7:
                if values[6]!=0:raise ValueError('unsupported native SQE flags')
                batch['sq'][uid]['sqe_flags']=values[6]
        elif line.startswith('RETURN '):
            if batch is None or 'returned' in batch or len(batch['sq'])!=batch['count']:raise ValueError('return outside submission phase')
            batch['returned']=int(line.split('=')[1])
        elif line.startswith('COMPLETIONS '):
            if batch is None or 'returned' not in batch or batch.get('cq_window'):raise ValueError('CQ window outside completion phase')
            fd,head,tail,mask=map(int,re.findall(r'=(\d+)',line))
            if fd!=batch['fd'] or mask!=511 or head!=batch['head'] or (tail-head)&0xffffffff!=batch['count']:raise ValueError('CQ window mismatch')
            batch['cq_window']=True
        elif line.startswith('CQE '):
            if batch is None or not batch.get('cq_window'):raise ValueError('CQE precedes completion window')
            uid,value,flags=map(int,re.findall(r'=(-?\d+)',line))
            if flags!=0:raise ValueError('unsupported native CQE flags')
            if not -(2**31)<=value<2**31 or not 0<=uid<2**64:raise ValueError('invalid native completion range')
            if uid in batch['cq'] or uid not in batch['sq']:raise ValueError('unknown or duplicate CQ identity')
            batch['cq'][uid]=dict(result=value,flags=flags)
        elif line=='BATCH_END':
            if batch is None:raise ValueError('batch end without batch')
            if not batch.get('cq_window') or batch.get('returned')!=batch['count'] or len(batch['sq'])!=batch['count'] or set(batch['sq'])!=set(batch['cq']):raise ValueError('incomplete batch')
            result.append(dict(submitter=batch['submitter'],ring_fd=batch['fd'],sq_head=batch['head'],sq_tail=batch['tail'],operations=[dict(**op,**batch['cq'][uid]) for uid,op in batch['sq'].items()]))
            last_tail[batch['fd']]=batch['tail']
            batch=None
    if batch is not None or not result:raise ValueError('missing batch end')
    outcomes=Counter(str(op['result']) for batch_result in result for op in batch_result['operations'])
    return dict(completion_results=dict(outcomes),successful_operations=sum(int(count) for value,count in outcomes.items() if int(value)>=0),failed_operations=sum(int(count) for value,count in outcomes.items() if int(value)<0),valid=True,kernel_layout_validated=require_setup,batches=result,operations=sum(len(b['operations']) for b in result),log_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),limitations=['binary-specific cooperative debugger probe','layout verified for observed setups' if require_setup else 'setup layout unverified','serialized batches only','no request ownership or kernel worker identity'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('log',type=Path)
    print(json.dumps(inspect(p.parse_args().log),indent=2))
