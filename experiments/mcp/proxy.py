#!/usr/bin/env python3
"""Transparent stdio MCP recorder; trace only the upstream server and descendants."""
import argparse
import asyncio
import hashlib
import json
import os
import signal
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent

async def main():
    p = argparse.ArgumentParser()
    p.add_argument('--run', type=Path, required=True)
    args = p.parse_args()
    run = args.run.resolve()
    (run / 'traces').mkdir(exist_ok=True)
    log = (run / 'protocol.jsonl').open('x', buffering=1)
    err = (run / 'server.stderr').open('w')
    settings = json.loads((run/'run-config.json').read_text()) if (run/'run-config.json').exists() else {}
    node_args = ['--import', str(HERE/'instrument.mjs')] if settings.get('instrumented') else []
    server = HERE/'control-server.mjs' if settings.get('scenario','read') not in {'read','fileops'} else HERE/'node_modules/@modelcontextprotocol/server-filesystem/dist/index.js'
    server_cmd=['node',*node_args,str(server),str(run/'sandbox')]
    if settings.get('runtime')=='tokio':
        server_cmd=[settings.get('tokio_binary',str(HERE.parent.parent/'target/tokio-provenance/debug/causpan-tokio-server')),
                    str(run/'sandbox'),'--worker-threads',str(settings.get('runtime_workers',2)),
                    '--blocking-threads',str(settings.get('pool_size',4))]
        expected=settings.get('tokio_binary_sha256')
        if expected and hashlib.sha256(Path(server_cmd[0]).read_bytes()).hexdigest()!=expected:
            raise RuntimeError('Tokio executable changed after run preparation')
    cmd=['strace','-ff','-ttt','-T','-yy','-s','4096','-e','trace=%file,%process,%desc,%network',
         '-o',str(run/'traces/strace'),*server_cmd]
    if settings.get('seccomp'):cmd.insert(2,'--seccomp-bpf')
    if settings.get('capture')=='off':cmd=server_cmd
    (run / 'trace-command.json').write_text(json.dumps(cmd, indent=2))
    child = await asyncio.create_subprocess_exec(*cmd, stdin=asyncio.subprocess.PIPE,
                                                stdout=asyncio.subprocess.PIPE, stderr=err, limit=16*1024*1024,
                                                env={**os.environ,'CAUSPAN_RUN':str(run),'CAUSPAN_INSTRUMENTED':'1' if settings.get('instrumented') else '0',
                                                     'UV_THREADPOOL_SIZE':str(settings.get('pool_size',4))})
    loop = asyncio.get_running_loop()
    incoming = asyncio.StreamReader(limit=16*1024*1024)
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(incoming), sys.stdin.buffer)

    async def pump(reader, direction):
        while line := await reader.readline():
            msg = json.loads(line)
            log.write(json.dumps({'wall_ns': time.time_ns(), 'mono_ns': time.monotonic_ns(),
                                  'direction': direction, 'message': msg}) + '\n')
            if direction == 'request':
                child.stdin.write(line)
                await child.stdin.drain()
            else:
                sys.stdout.buffer.write(line)
                sys.stdout.buffer.flush()
        if direction == 'request':
            child.stdin.close()

    tasks = [asyncio.create_task(pump(incoming, 'request')),
             asyncio.create_task(pump(child.stdout, 'response'))]
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, child.stdin.close)
    try:
        # Server exits when client closes stdin; child death must also stop input pump.
        done, _ = await asyncio.wait([*tasks, asyncio.create_task(child.wait())],
                                    return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
        await asyncio.wait_for(child.wait(), 10)
        await tasks[1]
        if child.returncode:
            raise RuntimeError(f'traced server exited {child.returncode}; see {run}/server.stderr')
    finally:
        for task in tasks:
            task.cancel()
        if child.returncode is None:
            child.terminate()
            await child.wait()
        log.close()
        err.close()

if __name__ == '__main__':
    asyncio.run(main())
