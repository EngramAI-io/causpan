#!/usr/bin/env python3
"""External SQE/CQE snapshots at cooperative stops; not a general kernel collector."""
import array
import mmap
import socket
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import time
from ring_observations import join_observations


def stopped(child, timeout=10):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        pid,status=os.waitpid(child.pid,os.WUNTRACED|os.WNOHANG)
        if pid:
            if os.WIFSTOPPED(status) and os.WSTOPSIG(status)==signal.SIGSTOP:return
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                child.returncode=os.waitstatus_to_exitcode(status)
            raise RuntimeError(f'helper did not reach snapshot stop: {status}')
        time.sleep(.005)
    raise TimeoutError('snapshot stop not reached')


def read_memory(pid,address,size):
    if not 0<size<=1024*1024:raise ValueError('unsupported mapping size')
    fd=os.open(f'/proc/{pid}/mem',os.O_RDONLY)
    try:data=os.pread(fd,size,address)
    finally:os.close(fd)
    if len(data)!=size:raise ValueError('short memory read')
    return data


def decode(meta,sq,sqes,cq):
    required=['sq_entries','cq_entries','sq_size','cq_size','sq_array','cqes',
              'sq_head','sq_tail','sq_mask','cq_head','cq_tail','cq_mask']
    if any(type(meta.get(key)) is not int or meta[key]<0 for key in required):
        raise ValueError('invalid snapshot layout metadata')
    if len(sq)!=meta['sq_size'] or len(cq)!=meta['cq_size'] or len(sqes)!=meta['sq_entries']*64:
        raise ValueError('snapshot length differs from layout')
    for kind,data in [('sq',sq),('cq',cq)]:
        offsets=[meta[kind+'_'+field] for field in ['head','tail','mask']]
        if len(set(offsets))!=3 or any(offset%4 or offset+4>len(data) for offset in offsets):
            raise ValueError('invalid ring counter offsets')
        base=meta['sq_array' if kind=='sq' else 'cqes']
        stride=4 if kind=='sq' else 16
        if base%stride or base+meta[kind+'_entries']*stride>len(data):
            raise ValueError('ring entries outside snapshot')
        if any(base<=offset<base+meta[kind+'_entries']*stride for offset in offsets):
            raise ValueError('ring counters overlap entries')
    def u32(data,offset):return struct.unpack_from('<I',data,offset)[0]
    records=[]
    for kind,data in [('sq',sq),('cq',cq)]:
        head=u32(data,meta[kind+'_head']);tail=u32(data,meta[kind+'_tail'])
        mask=u32(data,meta[kind+'_mask']);entries=meta[kind+'_entries']
        count=(tail-head)&0xffffffff
        if entries<1 or entries&(entries-1) or mask!=entries-1 or count>entries:
            raise ValueError('invalid ring counters or mask')
        for i in range(count):
            index=(head+i)&mask
            if kind=='sq':
                entry=u32(data,meta['sq_array']+index*4)
                if entry>=entries:raise ValueError('SQ index outside mapping')
                base=entry*64
                # The controlled helper zeroes every auxiliary field. Do not
                # silently project richer operations onto its smaller schema.
                if any(sqes[base+2:base+4]) or any(sqes[base+28:base+32]) or any(sqes[base+40:base+64]):
                    raise ValueError('unsupported auxiliary SQE fields')
                opcode,flags,_,fd,offset,_,length=struct.unpack_from('<BBHiQQI',sqes,base)
                identity=struct.unpack_from('<Q',sqes,base+32)[0]
                records.append(dict(kind='sqe',user_data=identity,opcode=opcode,flags=flags,fd=fd,offset=offset,length=length))
            else:
                identity,result,flags=struct.unpack_from('<QiI',data,meta['cqes']+index*16)
                records.append(dict(kind='cqe',user_data=identity,result=result,flags=flags))
    return records


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('output',type=Path)
    parser.add_argument('--export-ring',action='store_true',help='Map a cooperatively transferred ring descriptor')
    args=parser.parse_args()
    run=args.output.resolve();run.mkdir(parents=True,exist_ok=False)
    source=Path(__file__).with_name('io_uring_probe.c');binary=run/'helper'
    subprocess.run(['gcc','-Wall','-Wextra','-Werror','-O2',str(source),'-o',str(binary)],check=True)
    parent,peer=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
    ring_fd=None
    mappings=[]
    def mapped_snapshot(size,offset):
        mapping=mmap.mmap(ring_fd,size,flags=mmap.MAP_SHARED,prot=mmap.PROT_READ,offset=offset)
        mappings.append(mapping)
        return mapping[:]
    with (run/'stdout.jsonl').open('w') as out,(run/'metadata.jsonl').open('w') as err:
        child=subprocess.Popen([str(binary),str(run/'fixture.bin')],stdout=out,stderr=err,
                               env={**os.environ,'CAUSPAN_RING_SNAPSHOT':'1',**({'CAUSPAN_RING_EXPORT_FD':str(peer.fileno())} if args.export_ring else {})},
                               pass_fds=(peer.fileno(),) if args.export_ring else ())
        peer.close()
        try:
            stopped(child)
            meta=json.loads((run/'metadata.jsonl').read_text())
            if args.export_ring:
                parent.settimeout(5)
                data,ancillary,flags,_=parent.recvmsg(1,socket.CMSG_SPACE(array.array('i').itemsize))
                if data!=b'R' or flags or len(ancillary)!=1:raise ValueError('invalid descriptor export')
                level,kind,payload=ancillary[0]
                if level!=socket.SOL_SOCKET or kind!=socket.SCM_RIGHTS:raise ValueError('missing ring descriptor')
                descriptors=array.array('i');descriptors.frombytes(payload)
                if len(descriptors)!=1:raise ValueError('unexpected descriptor count')
                ring_fd=descriptors[0]
                sq=mapped_snapshot(meta['sq_size'],0)
                sqes=mapped_snapshot(meta['sq_entries']*64,0x10000000)
            else:
                sq=read_memory(child.pid,meta['sq'],meta['sq_size'])
                sqes=read_memory(child.pid,meta['sqes'],meta['sq_entries']*64)
            os.kill(child.pid,signal.SIGCONT);stopped(child)
            cq=mapped_snapshot(meta['cq_size'],0x8000000) if args.export_ring else read_memory(child.pid,meta['cq'],meta['cq_size'])
            for name,data in [('sq.bin',sq),('sqes.bin',sqes),('cq.bin',cq)]: (run/name).write_bytes(data)
            records=decode(meta,sq,sqes,cq);operations=join_observations(records)
            os.kill(child.pid,signal.SIGCONT)
            if child.wait(timeout=10)!=0:raise RuntimeError('helper failed')
        except Exception as error:
            (run/'report.json').write_text(json.dumps(dict(valid=False,stage='external_memory_snapshot',error=repr(error)),indent=2)+'\n')
            raise
        finally:
            if child.poll() is None:child.kill();child.wait()
            for mapping in mappings:mapping.close()
            if ring_fd is not None:os.close(ring_fd)
            parent.close()
    witness=[json.loads(line) for line in (run/'stdout.jsonl').read_text().splitlines()]
    if records!=witness:raise ValueError('external memory differs from runtime records')
    contents=(run/'fixture.bin').read_bytes()
    if contents[:7]!=b'uring-A' or contents[128:135]!=b'uring-B':raise ValueError('file content mismatch')
    for operation in operations:operation['evidence']='external_ring_memory_at_cooperative_stop'
    report=dict(valid=True,operations=operations,observation='external parent reads of actual ring mappings at cooperative SIGSTOP boundaries',
                access_method='transferred_ring_descriptor_mmap' if args.export_ring else 'proc_pid_mem',
                limitations=['helper supplies mapping metadata and optionally transfers its ring descriptor','little-endian 64-byte SQE / 16-byte CQE layout only','no MCP ownership or kernel worker identity','stops perturb execution; not asynchronous race-safe capture'],
                sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [source,Path(__file__),binary,*[run/n for n in ['sq.bin','sqes.bin','cq.bin','stdout.jsonl','metadata.jsonl','fixture.bin']]]})
    (run/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

if __name__=='__main__':main()
