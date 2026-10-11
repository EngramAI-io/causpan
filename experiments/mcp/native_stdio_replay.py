"""External JSON-RPC replay over dedicated inferior stdio pipes under GDB."""
import json
import os
import select
import shlex
import signal
import subprocess
import time


def capture(command,env,run,output,count,concurrency):
    incoming,writer=os.pipe();reader,outgoing=os.pipe()
    script=run/'stdio.gdb'
    original=(run/'source/windows.gdb').read_text()
    script.write_text(original.replace('\nrun\n','\nrun '+ ' '.join(shlex.quote(x) for x in command[command.index('--args')+2:])+' < /dev/fd/%d > /dev/fd/%d\n' % (incoming,outgoing)))
    command=list(command);command[command.index('-x')+1]=str(script)
    child=subprocess.Popen(command,env=env,stdout=output,stderr=subprocess.STDOUT,
                           stdin=subprocess.DEVNULL,pass_fds=(incoming,outgoing),start_new_session=True)
    os.close(incoming);os.close(outgoing)
    deadline=time.monotonic()+120;buffer=b'';protocol=[];oracle=[]
    def send(message):
        data=(json.dumps(message)+'\n').encode();offset=0
        while offset<len(data):offset+=os.write(writer,data[offset:])
        protocol.append(dict(direction='send',message=message))
    def receive():
        nonlocal buffer
        while b'\n' not in buffer:
            remaining=deadline-time.monotonic()
            if remaining<=0 or not select.select([reader],[],[],remaining)[0]:raise TimeoutError('MCP stdio response timeout')
            chunk=os.read(reader,65536)
            if not chunk:raise RuntimeError('MCP stdio closed before response')
            buffer+=chunk
        line,buffer=buffer.split(b'\n',1);message=json.loads(line)
        protocol.append(dict(direction='receive',message=message));return message
    try:
        send(dict(jsonrpc='2.0',id=0,method='initialize',params=dict(protocolVersion='2024-11-05',capabilities={},clientInfo=dict(name='native-replay',version='1'))))
        result=receive()
        if result.get('id')!=0 or 'result' not in result:raise ValueError('initialize failed')
        send(dict(jsonrpc='2.0',method='notifications/initialized'))
        responses=[]
        for start in range(0,count,concurrency):
            pending=set(range(start+1,min(start+concurrency,count)+1))
            for identity in sorted(pending):
                token='stdio-'+str(identity);oracle.append(dict(kind='request',rpc_id=identity,token=token))
                send(dict(jsonrpc='2.0',id=identity,method='tools/call',params=dict(name='roundtrip',arguments=dict(token=token))))
            while pending:
                result=receive()
                if result.get('id') not in pending or 'result' not in result or result['result'].get('isError'):
                    raise ValueError('unexpected or failed MCP response')
                pending.remove(result['id']);responses.append(result)
        os.close(writer);writer=None
        code=child.wait(timeout=max(0.1,deadline-time.monotonic()))
        path=run/'socket-oracle.json';path.write_text(json.dumps(oracle+json.loads(path.read_text()),indent=2)+'\n')
        (run/'mcp-responses.json').write_text(json.dumps(responses,indent=2)+'\n')
        return code
    finally:
        if writer is not None:os.close(writer)
        os.close(reader)
        if child.poll() is None:os.killpg(child.pid,signal.SIGKILL);child.wait()
        (run/'stdio-protocol.json').write_text(json.dumps(protocol,indent=2)+'\n')
