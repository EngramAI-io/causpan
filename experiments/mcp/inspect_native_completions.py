#!/usr/bin/env python3
"""Verify the bounded first-batch Node debugger experiment, not arbitrary GDB logs."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct


def inspect(path):
    text=path.read_text()
    if 'exited normally' not in text or 'Error in sourced' in text:raise ValueError('debugger run incomplete')
    batches=[];current=None;mode=None
    for line in text.splitlines():
        if line.startswith('RING_ENTER '):
            if current is not None:raise ValueError('overlapping debugger batches unsupported')
            values=list(map(int,re.findall(r'=(\d+)',line)))
            if values[1:]!=[2,2,1]:raise ValueError('unsupported enter shape')
            current=dict(fd=values[0],sq=bytearray(),cq=bytearray());mode=None
        elif line.startswith('SQ_COUNTERS '):
            if line!='SQ_COUNTERS head=0 tail=2 mask=255':raise ValueError('unsupported SQ window')
            current['sq_window_verified']=True;mode='sq'
        elif line.startswith('SQ_ARRAY '):
            if line!='SQ_ARRAY index0=0 index1=1':raise ValueError('unexpected SQ indirection')
            current['array_verified']=True;mode=None
        elif line.startswith('ENTER_RETURN '):
            if line!='ENTER_RETURN result=2':raise ValueError('partial or failed enter')
            current['returned']=True
        elif line.startswith('CQ_RING '):
            if line!=f"CQ_RING fd={current['fd']} mask=511":raise ValueError('CQ ring mismatch')
            current['cq_ring_verified']=True
        elif line.startswith('CQ_COUNTERS '):
            if line!='CQ_COUNTERS head=0 tail=2':raise ValueError('unsupported CQ window')
            current['cq_window_verified']=True;mode='cq'
        elif mode and re.match(r'^0x[0-9a-f]+:\s+0x',line):
            current[mode].extend(int(x,16) for x in re.findall(r'0x([0-9a-f]{2})(?=\s|$)',line.split(':',1)[1]))
            if mode=='cq' and len(current['cq'])==32:
                if len(current['sq'])!=128 or not current.get('array_verified') or not current.get('returned') or not current.get('sq_window_verified') or not current.get('cq_ring_verified') or not current.get('cq_window_verified'):raise ValueError('incomplete SQ/enter evidence')
                submissions={}
                for offset in [0,64]:
                    identity=struct.unpack_from('<Q',current['sq'],offset+32)[0]
                    if identity in submissions:raise ValueError('duplicate submission identity')
                    submissions[identity]=dict(user_data=identity,opcode=current['sq'][offset],fd=struct.unpack_from('<i',current['sq'],offset+4)[0])
                for offset in [0,16]:
                    identity,result,flags=struct.unpack_from('<QiI',current['cq'],offset)
                    if identity not in submissions:raise ValueError('unknown or duplicate completion')
                    operation=submissions.pop(identity);operation.update(result=result,flags=flags,ring_fd=current['fd']);batches.append(operation)
                if submissions:raise ValueError('missing completions')
                current=None;mode=None
    if current is not None or not batches:raise ValueError('incomplete capture')
    return dict(valid=True,operations=batches,log_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),scope='Controlled first-batch SQ/CQ identity validation; setup metadata validation is separate; no MCP ownership inferred.')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('log',type=Path)
    print(json.dumps(inspect(p.parse_args().log),indent=2))
