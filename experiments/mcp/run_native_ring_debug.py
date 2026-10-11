#!/usr/bin/env python3
"""Run the binary-specific native ring debugger experiment with identity checks."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
from inspect_native_windows import inspect
from native_socket_lifetimes import report as socket_report
from native_resource_context import report as context_report
from score_native_resources import score as resource_score
from native_graph import build as native_graph
from score_native_graph import score as graph_score
from native_stdio_replay import capture as stdio_capture
from native_agent import capture as agent_capture

HERE=Path(__file__).resolve().parent
EXPECTED_NODE='23a5637c2470fde09fcc1acc77c1b92e04e3d7e3e6e80ff7df6f5831958d1477'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path);parser.add_argument('--connections',type=int,default=4)
    parser.add_argument('--mcp-replay',action='store_true')
    parser.add_argument('--concurrency',type=int,default=1)
    parser.add_argument('--shared-watcher',action='store_true')
    parser.add_argument('--mcp-stdio',action='store_true')
    parser.add_argument('--agent',action='store_true')
    args=parser.parse_args()
    if args.agent:args.mcp_stdio=True
    if args.mcp_stdio:args.mcp_replay=True
    if args.mcp_stdio and args.shared_watcher:parser.error('stdio shared workload not yet supported')
    if args.shared_watcher and (not args.mcp_replay or args.concurrency!=args.connections):parser.error('shared watcher requires MCP replay and one full concurrent batch')
    if not 1<=args.concurrency<=args.connections:parser.error('concurrency must be 1..connections')
    if args.concurrency!=1 and not args.mcp_replay:parser.error('concurrency requires --mcp-replay')
    if not 1<=args.connections<=1000:parser.error('connections must be 1..1000')
    node=Path(shutil.which('node')).resolve()
    digest=hashlib.sha256(node.read_bytes()).hexdigest()
    if digest!=EXPECTED_NODE:raise SystemExit('Unsupported Node binary: debugger addresses are pinned')
    run=args.output.resolve();run.mkdir(parents=True,exist_ok=False)
    workload='mcp-network.mjs' if args.mcp_replay else 'network.cjs'
    sources=[HERE/'node-ring-debug/windows.gdb',HERE/'node-ring-debug'/workload,HERE/'inspect_native_windows.py',HERE/'native_socket_lifetimes.py',Path(__file__)]
    snapshot=run/'source';snapshot.mkdir()
    if args.mcp_replay:
        for source in ['native_agent.py','native_stdio_proxy.py','native_stdio_replay.py','score_native_graph.py','native_graph.py','native_preparation.py','native_watcher_queue.py','native_watcher_operations.py','native_retry_ancestry.py','score_native_resources.py','native_resource_context.py','native_marker_timeline.py','instrument.mjs','native/context.node','native/build.json','native/context.cc']:
            sources.append(HERE/source)
    for path in sources:shutil.copyfile(path,snapshot/path.name)
    manifest=dict(node=str(node),node_sha256=digest,connections=args.connections,mcp_replay=args.mcp_replay,mcp_stdio=args.mcp_stdio,agent=args.agent,shared_watcher=args.shared_watcher,concurrency=args.concurrency,status='running',
                  source_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sources})
    env=os.environ.copy()
    env.update(CAUSPAN_RUN=str(run),CAUSPAN_MCP_ROOT=str(HERE),CAUSPAN_MCP_CONCURRENCY=str(args.concurrency),CAUSPAN_SHARED_WATCHER='1' if args.shared_watcher else '0')
    env['CAUSPAN_MCP_STDIO']='1' if args.mcp_stdio else '0'
    node_args=['--import',str(HERE/'instrument.mjs')] if args.mcp_replay else []
    try:
        with (run/'debugger.log').open('w') as out:
            command=['gdb','-q','-batch','-x',str(snapshot/'windows.gdb'),'--args',str(node),*node_args,str(snapshot/workload),str(args.connections)]
            if args.agent:
                code=agent_capture(command,env,run,HERE,args.connections)
            elif args.mcp_stdio:
                code=stdio_capture(command,env,run,out,args.connections,args.concurrency)
            else:
                child=subprocess.Popen(command,env=env,stdout=out,stderr=subprocess.STDOUT,start_new_session=True)
                try:code=child.wait(timeout=120)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid,signal.SIGKILL);child.wait();raise
        if code:raise RuntimeError(f'debugger exited {code}')
        report=inspect(run/'debugger.log',require_setup=True)
        (run/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        lifetimes=socket_report(run/'debugger.log')
        (run/'socket-lifetimes.json').write_text(json.dumps(lifetimes,indent=2)+'\n')
        resources=socket_report(run/'debugger.log',include_controls=True)
        (run/'resource-lifetimes.json').write_text(json.dumps(resources,indent=2)+'\n')
        manifest.update(resource_links=resources['linked'],unresolved_resource_targets=resources['unresolved'],resource_lifetimes_sha256=hashlib.sha256((run/'resource-lifetimes.json').read_bytes()).hexdigest())
        manifest.update(socket_links=lifetimes['linked'],unresolved_socket_targets=lifetimes['unresolved'],socket_lifetimes_sha256=hashlib.sha256((run/'socket-lifetimes.json').read_bytes()).hexdigest())
        if args.mcp_replay:
            graph=native_graph(run)
            (run/'native-graph.json').write_text(json.dumps(graph,indent=2)+'\n')
            manifest.update(native_graph_sha256=hashlib.sha256((run/'native-graph.json').read_bytes()).hexdigest())
            graph_checks=graph_score(run,graph)
            (run/'graph-score.json').write_text(json.dumps(graph_checks,indent=2)+'\n')
            manifest.update(graph_score_sha256=hashlib.sha256((run/'graph-score.json').read_bytes()).hexdigest())
            if graph_checks['mismatches'] or (not args.shared_watcher and graph_checks['covered_requests']!=args.connections):
                raise RuntimeError('graph ancestry oracle failed')
            ancestry=context_report(run)
            (run/'resource-context.json').write_text(json.dumps(ancestry,indent=2)+'\n')
            score=resource_score(run)
            (run/'resource-score.json').write_text(json.dumps(score,indent=2)+'\n')
            manifest.update(resource_score_sha256=hashlib.sha256((run/'resource-score.json').read_bytes()).hexdigest())
            if score['mismatches'] or (not args.shared_watcher and score['covered_requests']!=score['requests']):
                raise RuntimeError('resource ancestry oracle failed')
            manifest.update(resource_context_sha256=hashlib.sha256((run/'resource-context.json').read_bytes()).hexdigest())
        manifest.update(status='complete',batches=len(report['batches']),operations=report['operations'],report_sha256=hashlib.sha256((run/'report.json').read_bytes()).hexdigest())
    except Exception as error:
        manifest.update(status='failed',error=repr(error));raise
    finally:(run/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(manifest,indent=2))

if __name__=='__main__':main()
