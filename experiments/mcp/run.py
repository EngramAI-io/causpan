#!/usr/bin/env python3
"""Run a real Codex agent or deterministic MCP concurrency control."""
import argparse
import asyncio
import json
import hashlib
import uuid
import platform
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent

async def replay(run, concurrency, shared, scenario="read", batches=4, string_ids=False, spoof_context=False):
    echo_server=None
    shared_peer=None
    echo_port=None
    if scenario in {'network','network-shared'}:
        async def echo(reader,writer):
            try:
                while payload:=await reader.readline():
                    writer.write(payload)
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
        echo_server=await asyncio.start_server(echo,'127.0.0.1',0)
        echo_port=echo_server.sockets[0].getsockname()[1]
        (run/'network-fixture.json').write_text(json.dumps({'host':'127.0.0.1','port':echo_port,'traced':False}))
    elif scenario in {'network-inbound','network-inbound-shared'}:
        with socket.socket() as probe:
            probe.bind(('127.0.0.1',0));echo_port=probe.getsockname()[1]
        (run/'network-fixture.json').write_text(json.dumps({'host':'127.0.0.1','port':echo_port,'traced':True}))
    child = await asyncio.create_subprocess_exec(sys.executable, str(HERE / 'proxy.py'),
        '--run', str(run), stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, limit=16*1024*1024)
    batch_extra={"batch_width":concurrency} if json.loads((run/"run-config.json").read_text()).get("runtime")=="tokio" else {}
    seq = 0
    pending = {}
    async def receive():
        while line := await child.stdout.readline():
            msg = json.loads(line)
            if 'id' in msg and msg['id'] in pending:
                pending.pop(msg['id']).set_result(msg)
        for f in pending.values():
            if not f.done(): f.set_exception(RuntimeError('MCP server closed'))
    reader = asyncio.create_task(receive())
    async def call(method, params):
        nonlocal seq
        seq += 1
        f = asyncio.get_running_loop().create_future()
        request_id=f'request-{seq}' if string_ids else seq
        pending[request_id] = f
        if spoof_context and method=='tools/call':params={**params,'_meta':{'org.causpan/context':999999,'org.causpan/request':1}}
        child.stdin.write((json.dumps({'jsonrpc':'2.0', 'id':request_id, 'method':method,
                                      'params':params})+'\n').encode())
        await child.stdin.drain()
        result = await asyncio.wait_for(f, 60)
        if scenario in {'worker-crash','worker-fatal','worker-relay-fatal','worker-wrong-response'} and params.get('name')=='worker_slot':
            if not result.get('result',{}).get('isError'):
                raise RuntimeError('crashed worker unexpectedly succeeded')
            return result
        if 'error' in result or result.get('result', {}).get('isError'):
            raise RuntimeError(result)
        return result
    try:
        await call('initialize', {'protocolVersion':'2024-11-05','capabilities':{},
                                 'clientInfo':{'name':'causpan-control','version':'1'}})
        child.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        await call('tools/list', {})
        for batch in range(batches):
            if scenario in {'network','network-shared'}:
                await asyncio.gather(*(call('tools/call',{'name':'tcp_roundtrip',
                    'arguments':{'slot':batch*concurrency+i,'port':echo_port}}) for i in range(concurrency)))
                continue
            if scenario=='network-inbound-shared':
                if shared_peer is None:
                    shared_peer=await asyncio.open_connection('127.0.0.1',echo_port)
                peer_reader,writer=shared_peer
                requests=[asyncio.create_task(call('tools/call',{'name':'tcp_accept','arguments':{'slot':batch*concurrency+i}}))
                          for i in range(concurrency)]
                await asyncio.sleep(0.05)
                tokens=[f'causpan-in:{batch*concurrency+i}\n' for i in range(concurrency)]
                writer.write(''.join(tokens).encode());await writer.drain()
                replies=set()
                for _ in range(concurrency):
                    replies.add(await asyncio.wait_for(peer_reader.readline(),5))
                if replies!={token.encode() for token in tokens}:raise RuntimeError('inbound shared TCP response mismatch')
                await asyncio.gather(*requests)
                continue
            if scenario=='network-inbound':
                async def roundtrip(slot):
                    request=asyncio.create_task(call('tools/call',{'name':'tcp_accept','arguments':{'slot':slot}}))
                    await asyncio.sleep(0.05)
                    reader,writer=await asyncio.open_connection('127.0.0.1',echo_port)
                    token=f'causpan-in:{slot}\n'
                    writer.write(token.encode());await writer.drain()
                    response=await asyncio.wait_for(reader.readline(),5)
                    writer.close();await writer.wait_closed()
                    if response.decode()!=token:raise RuntimeError('inbound TCP response mismatch')
                    await request
                await asyncio.gather(*(roundtrip(batch*concurrency+i) for i in range(concurrency)))
                continue
            if scenario == "fileops":
                for step in range(6):
                    calls=[]
                    for i in range(concurrency):
                        path=str(run/'sandbox'/f'work-{batch}-{i}.txt')
                        destination=str(run/'sandbox'/f'renamed-{batch}-{i}.txt')
                        token=f'causpan:{batch}:{i}'
                        name,arguments=[('write_file',{'path':path,'content':token}),
                            ('read_text_file',{'path':path}),
                            ('edit_file',{'path':path,'edits':[{'oldText':token,'newText':token+':edited'}]}),
                            ('move_file',{'source':path,'destination':destination}),
                            ('read_multiple_files',{'paths':[destination,str(run/'sandbox/link.txt')]}),
                            ('get_file_info',{'path':destination})][step]
                        calls.append(call('tools/call',{'name':name,'arguments':arguments}))
                    await asyncio.gather(*calls)
                for i in range(concurrency):
                    if (run/'sandbox'/f'renamed-{batch}-{i}.txt').read_text()!=f'causpan:{batch}:{i}:edited':
                        raise RuntimeError('fileops final content mismatch')
                    if (run/'sandbox'/f'work-{batch}-{i}.txt').exists():raise RuntimeError('move_file left source behind')
                continue
            if scenario != "read":
                await asyncio.gather(*(call("tools/call", {"name":"spawn_slot" if scenario=="spawn" else "clone_files_slot" if scenario=="clone-files" else "worker_slot" if scenario in {"worker-context","worker-unscoped","worker-failure","worker-crash","worker-cancel","worker-spawn","worker-grandchild","worker-socketpair","worker-fatal","worker-relay","worker-relay-fatal","worker-wrong-response"} else "cancel_probe" if scenario=="cancel" else "fail_probe" if scenario=="failure" else "batch_io" if scenario in {"batch","batch-joined"} else "slot_io",
                    "arguments":{"slot":batch*concurrency+i, **({"joined":scenario=="batch-joined",**batch_extra} if scenario in {"batch","batch-joined"} else {"cancel":bool(i%2)} if scenario=="cancel" else {} if scenario in {"spawn","failure","clone-files","worker-context","worker-unscoped","worker-failure","worker-crash","worker-cancel","worker-spawn","worker-grandchild","worker-socketpair","worker-fatal","worker-relay","worker-relay-fatal","worker-wrong-response"} else
                    {"rounds":3,"delay_ms":2,"nested":scenario=="nested","detached":scenario=="detached"})}})
                    for i in range(concurrency)))
                continue
            await asyncio.gather(*(call('tools/call', {'name':'read_text_file', 'arguments':{
                'path':str(run / 'sandbox' / ('shared.txt' if shared else f'call-{batch}-{i}.txt'))}})
                for i in range(concurrency)))
        if scenario not in {"read","fileops"}: await call("tools/call", {"name":"barrier","arguments":{}})
    finally:
        if shared_peer:
            shared_peer[1].close()
            await shared_peer[1].wait_closed()
        if echo_server:
            echo_server.close()
            await echo_server.wait_closed()
        child.stdin.close()
        try:
            await asyncio.wait_for(child.wait(), 5)
        except asyncio.TimeoutError:
            child.terminate()
            try:
                await asyncio.wait_for(child.wait(), 2)
            except asyncio.TimeoutError:
                child.kill()
                await child.wait()
        await asyncio.gather(reader,return_exceptions=True)
    if child.returncode: raise RuntimeError(f'proxy exited {child.returncode}')



def validate_agent(run):
    """Require actual successful MCP operations, not just an agent's claim of completion."""
    rows = [json.loads(line) for line in (run/'agent.jsonl').read_text().splitlines()]
    items = [r['item'] for r in rows if r.get('type') == 'item.completed']
    if any(i.get('type') == 'command_execution' for i in items):
        raise RuntimeError('agent used shell; run is not an MCP-only experiment')
    calls = [i for i in items if i.get('type') == 'mcp_tool_call']
    if any(i.get('server') != 'causpan_fs' or i.get('status') != 'completed' for i in calls):
        raise RuntimeError('agent used another server or a tool failed')
    expected = [('read_text_file', 'call-0-0.txt'), ('read_text_file', 'call-1-0.txt'),
                ('write_file', 'agent-summary.txt'), ('read_text_file', 'agent-summary.txt')]
    for tool, name in expected:
        if not any(i.get('tool') == tool and i.get('arguments',{}).get('path') ==
                   str(run/'sandbox'/name) for i in calls):
            raise RuntimeError(f'agent did not complete expected MCP operation: {tool} {name}')
    if not any(r.get('type') == 'turn.completed' for r in rows):
        raise RuntimeError('agent turn did not complete')
    if not (run/'sandbox/agent-summary.txt').is_file():
        raise RuntimeError('agent summary file missing')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--runtime',choices=['node','tokio'],default='node')
    p.add_argument('--tokio-binary',type=Path,help='Explicit Tokio server build to capture')
    p.add_argument('--runtime-workers',type=int,default=2,help='Tokio async worker threads')
    p.add_argument('--mode', choices=['agent','replay'], default='replay')
    p.add_argument('--concurrency', type=int, default=8)
    p.add_argument('--shared', action='store_true')
    p.add_argument('--instrumented', action='store_true')
    p.add_argument('--pool-size', type=int, default=4)
    p.add_argument('--scenario',choices=['read','fileops','slots','nested','detached','spawn','clone-files','worker-context','worker-unscoped','worker-failure','worker-crash','worker-cancel','worker-spawn','worker-grandchild','worker-socketpair','worker-fatal','worker-relay','worker-relay-fatal','worker-wrong-response','cancel','failure','batch','batch-joined','network','network-shared','network-inbound','network-inbound-shared'],default='read')
    p.add_argument('--batches',type=int,default=4)
    p.add_argument('--seccomp',action='store_true',help='Use strace seccomp filtering to reduce ptrace stops')
    p.add_argument('--string-ids',action='store_true')
    p.add_argument('--spoof-context',action='store_true')
    p.add_argument('--capture',choices=['strace','strace-all','off'],default='strace')
    p.add_argument('--model', help='Optional Codex model override')
    p.add_argument('--output', type=Path)
    args = p.parse_args()
    if args.concurrency < 1 or args.batches < 1 or not 1 <= args.pool_size <= 128:
        p.error('positive concurrency/batches and pool size 1..128 required')
    if args.runtime=='tokio' and args.scenario not in {'read','slots','nested','detached','spawn','cancel','failure','batch','batch-joined'}:p.error('Tokio does not yet support this scenario')
    if args.mode=='agent' and (args.scenario!='read' or args.batches<2):p.error('agent mode requires read scenario and at least two fixture batches')
    if args.scenario in {'cancel','failure'} and not args.instrumented:p.error('cancel scenario requires --instrumented')
    if args.scenario in {'clone-files','worker-context','worker-unscoped','worker-failure','worker-crash','worker-cancel','worker-spawn','worker-grandchild','worker-socketpair','worker-fatal','worker-relay','worker-relay-fatal','worker-wrong-response'} and (args.runtime!='node' or not args.instrumented):p.error('clone-files and worker scenarios require the instrumented Node runtime')
    if args.instrumented and args.runtime=='node' and not (HERE/'native/context.node').exists():p.error('build addon first: python3.11 experiments/mcp/native/build.py')
    for exe in ['strace'] + (['node'] if args.runtime=='node' else ['rustc']) + (['gcc'] if args.scenario=='clone-files' else []) + (['codex'] if args.mode == 'agent' else []):
        if not shutil.which(exe): p.error(f'missing {exe}')
    if args.runtime=='node' and not (HERE / 'node_modules').exists(): p.error('run npm ci --prefix experiments/mcp')
    tokio_binary=(args.tokio_binary or HERE.parent.parent/'target/tokio-provenance/debug/causpan-tokio-server').resolve()
    if args.runtime=='tokio' and not tokio_binary.exists():p.error('Build causpan-tokio-server with --cfg tokio_unstable in target/tokio-provenance first')
    tokio_digest=None
    build_provenance=None
    if args.runtime=='tokio':
        tokio_digest=hashlib.sha256(tokio_binary.read_bytes()).hexdigest()
        build_file=tokio_binary.with_suffix('.build.json')
        if build_file.exists():
            from build_tokio import source_hashes
            build_provenance=json.loads(build_file.read_text())
            if build_provenance['binary_sha256']!=tokio_digest or build_provenance['sources']!=source_hashes():
                p.error('Tokio binary/source mismatch; rebuild with experiments/mcp/build_tokio.py')
    run = (args.output or HERE.parent.parent / 'results/mcp' /
           f'{time.time_ns()}-{args.mode}-c{args.concurrency}').resolve()
    run.mkdir(parents=True, exist_ok=False)
    session_id=uuid.uuid4().hex
    helper_binary=run/'clone_files_probe'
    (run/'run-config.json').write_text(json.dumps({'session_id':session_id,'runtime':args.runtime,'tokio_binary':str(tokio_binary),'tokio_binary_sha256':tokio_digest,'clone_files_binary':str(helper_binary),'runtime_workers':args.runtime_workers,'instrumented':args.instrumented,'pool_size':args.pool_size,'scenario':args.scenario,'capture':args.capture,'seccomp':args.seccomp}))
    snapshot=run/'code';snapshot.mkdir()
    if build_provenance is not None:
        (snapshot/'tokio-build.json').write_text(json.dumps(build_provenance,indent=2)+'\n')
    sources=[*HERE.glob('*.py'),*HERE.glob('*.mjs'),HERE/'clone_files_probe.c',HERE/'native/context.cc',HERE/'native/build.py',HERE/'native/build.json',HERE/'package-lock.json']
    hashes={}
    for source in sources:
        if source.exists():
            relative=source.relative_to(HERE)
            target=snapshot/relative;target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(source,target)
            hashes[str(relative)]=hashlib.sha256(source.read_bytes()).hexdigest()
    if args.instrumented and args.runtime=='node':
        hashes['native/context.node']=hashlib.sha256((HERE/'native/context.node').read_bytes()).hexdigest()
    if args.runtime=='tokio':
        repo=HERE.parent.parent
        rust_sources=[repo/'Cargo.toml',repo/'Cargo.lock',*(repo/'crates/causpan-runtime').rglob('*.rs'),repo/'crates/causpan-runtime/Cargo.toml',*(repo/'crates/causpan-tokio-server').rglob('*.rs'),repo/'crates/causpan-tokio-server/Cargo.toml']
        for source in rust_sources:
            relative=Path('rust')/source.relative_to(repo)
            target=snapshot/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
            hashes[str(relative)]=hashlib.sha256(source.read_bytes()).hexdigest()
        hashes['causpan-tokio-server']=hashlib.sha256(tokio_binary.read_bytes()).hexdigest()
    sandbox = run / 'sandbox'
    sandbox.mkdir()
    for batch in range(args.batches):
        for i in range(args.concurrency):
            (sandbox / f'call-{batch}-{i}.txt').write_text(f'fixture {batch}-{i}\n' + 'sample data\n'*512)
    (sandbox / 'slots.bin').write_bytes(b'\0'*128)
    (sandbox / 'shared.txt').write_text('shared fixture\n' * 512)
    (sandbox/'link.txt').symlink_to('shared.txt')
    versions = {x:subprocess.check_output([x,'--version'], text=True).splitlines()[0]
                for x in (['node','strace'] if args.runtime=='node' else ['rustc','strace']) + (['gcc'] if args.scenario=='clone-files' else []) + (['codex'] if args.mode == 'agent' else [])}
    manifest = dict(session_id=session_id,runtime=args.runtime,runtime_workers=args.runtime_workers,capture=args.capture,seccomp=args.seccomp,code_sha256=hashes,mode=args.mode, concurrency=args.concurrency, shared=args.shared,
                    instrumented=args.instrumented,pool_size=args.pool_size,string_ids=args.string_ids,spoof_context=args.spoof_context,scenario=args.scenario,batches=args.batches,
                    model=args.model, platform=platform.platform(), versions=versions,
                    server=json.loads((HERE/'package.json').read_text())['dependencies'] if args.runtime=='node' else {'causpan-tokio-server':subprocess.check_output([str(tokio_binary),'--version'],text=True).strip()},
                    status='running')
    print(f'Run: {run}', flush=True)
    started=time.monotonic()
    try:
        if args.scenario=='clone-files':
            subprocess.run(['gcc','-Wall','-Wextra','-O2',str(HERE/'clone_files_probe.c'),'-o',str(helper_binary)],check=True)
            manifest['clone_files_probe_sha256']=hashlib.sha256(helper_binary.read_bytes()).hexdigest()
        if args.mode == 'replay':
            asyncio.run(replay(run, args.concurrency, args.shared,args.scenario,args.batches,args.string_ids,args.spoof_context))
        else:
            prompt = f'''This is a filesystem MCP attribution experiment. Use ONLY tools from
causpan_fs. First use tool discovery/search to load the causpan_fs MCP tools if they are deferred. Do not assume unavailable merely because they are not initially listed. Never use shell, code execution, or other servers for file operations. Read these two files using
separate read_text_file tool calls, concurrently if possible:
{sandbox / 'call-0-0.txt'}
{sandbox / 'call-1-0.txt'}
Then use write_file to create {sandbox / 'agent-summary.txt'} with a short summary.
Then read agent-summary.txt back with read_text_file. Do not delegate. Stop after verifying.'''
            (run/'prompt.txt').write_text(prompt)
            config = {'mcp_servers.causpan_fs.command':sys.executable,
                      'mcp_servers.causpan_fs.args':[str(HERE/'proxy.py'),'--run',str(run)],
                      'mcp_servers.causpan_fs.required':True,
                      'mcp_servers.causpan_fs.tools.write_file.approval_mode':'approve',
                      'mcp_servers.causpan_fs.startup_timeout_sec':30,
                      'mcp_servers.causpan_fs.tool_timeout_sec':60,
                      'approval_policy':'never'}
            cmd = ['codex','exec','--ignore-user-config','--ephemeral','--skip-git-repo-check',
                   '--json','--sandbox','read-only','-C',str(sandbox)]
            for key,value in config.items():
                cmd += ['-c', f'{key}={json.dumps(value)}']
            if args.model: cmd += ['--model',args.model]
            cmd += [prompt]
            with (run/'agent.jsonl').open('w') as out, (run/'agent.stderr').open('w') as err:
                subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=out, stderr=err, check=True, timeout=240)
            validate_agent(run)
        manifest['execution_seconds']=time.monotonic()-started
        if args.capture!='off':
            subprocess.run([sys.executable,str(HERE/'analyze.py'),str(run)], check=True)
        if args.instrumented and args.capture!='off':
            subprocess.run([sys.executable,str(HERE/'attribute.py'),str(run)],check=True)
            if args.scenario=='fileops':subprocess.run([sys.executable,str(HERE/'score_fileops.py'),str(run)],check=True)
            if args.scenario not in {'read','fileops'}:
                subprocess.run([sys.executable,str(HERE/('score_network.py' if args.scenario in {'network','network-shared','network-inbound','network-inbound-shared'} else 'score_batch.py' if args.scenario in {'batch','batch-joined'} else 'score_control.py')),str(run)],check=True)
        manifest['status'] = 'complete'
    except Exception as e:
        manifest['status'] = 'failed'
        manifest['error'] = str(e)
        raise
    finally:
        (run/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')

if __name__ == '__main__': main()
