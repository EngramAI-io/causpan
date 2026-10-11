#!/usr/bin/env python3
"""Transparent MCP stdio bridge to a binary-pinned native debugger capture."""
import argparse
import json
import os
from pathlib import Path
import select
import shlex
import signal
import subprocess
import sys
import time


def main():
    p=argparse.ArgumentParser();p.add_argument('run',type=Path);a=p.parse_args();run=a.run.resolve()
    launch=json.loads((run/'native-launch.json').read_text());command=launch['command']
    env=os.environ.copy();env.update(launch['environment'])
    incoming,writer=os.pipe();reader,outgoing=os.pipe()
    script=run/'agent-stdio.gdb'
    script.write_text((run/'source/windows.gdb').read_text().replace('\nrun\n',
        '\nrun '+' '.join(shlex.quote(x) for x in command[command.index('--args')+2:])+f' < /dev/fd/{incoming} > /dev/fd/{outgoing}\n'))
    command[command.index('-x')+1]=str(script)
    protocol=[];oracle=[];buffers={0:b'',reader:b''};child=None;status='failed'
    shutting_down=[False]
    signal.signal(signal.SIGTERM,lambda *_:shutting_down.__setitem__(0,True))
    def forward(fd,data):
        offset=0
        while offset<len(data):offset+=os.write(fd,data[offset:])
    try:
        with (run/'debugger.log').open('w') as log:
            child=subprocess.Popen(command,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
                                   pass_fds=(incoming,outgoing),start_new_session=True)
            os.close(incoming);os.close(outgoing);deadline=time.monotonic()+240
            while not shutting_down[0]:
                remaining=deadline-time.monotonic()
                if remaining<=0:raise TimeoutError('native MCP bridge timeout')
                ready=select.select([0,reader],[],[],min(remaining,1))[0]
                if not ready:
                    if child.poll() is not None:break
                    continue
                stop=False
                for fd in ready:
                    data=os.read(fd,65536)
                    if not data:
                        stop=True;break
                    forward(writer if fd==0 else 1,data)
                    buffers[fd]+=data
                    while b'\n' in buffers[fd]:
                        line,buffers[fd]=buffers[fd].split(b'\n',1)
                        message=json.loads(line);protocol.append(dict(direction='send' if fd==0 else 'receive',message=message))
                        if fd==0 and message.get('method')=='tools/call':
                            oracle.append(dict(kind='request',rpc_id=message['id'],token=message['params']['arguments']['token']))
                if stop:break
            os.close(writer);writer=None
            code=child.wait(timeout=20)
            if code:raise RuntimeError('debugger failed')
            path=run/'socket-oracle.json';path.write_text(json.dumps(oracle+json.loads(path.read_text()),indent=2)+'\n')
            status='complete'
    finally:
        if writer is not None:os.close(writer)
        os.close(reader)
        if child is not None and child.poll() is None:os.killpg(child.pid,signal.SIGKILL);child.wait()
        (run/'stdio-protocol.json').write_text(json.dumps(protocol,indent=2)+'\n')
        (run/'bridge-status.json').write_text(json.dumps(dict(status=status))+'\n')

if __name__=='__main__':main()
