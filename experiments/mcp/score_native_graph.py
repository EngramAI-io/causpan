#!/usr/bin/env python3
"""Evaluate graph request ancestry with the separate client-token/socket oracle."""
import argparse
import hashlib
import json
from pathlib import Path
from native_graph import build


def evaluate(graph,oracle):
    tokens={};fds={}
    for row in oracle:
        if row['kind']=='request':
            if row['rpc_id'] in tokens:raise ValueError('duplicate oracle request')
            tokens[row['rpc_id']]=row['token']
        elif row['kind']=='socket':
            if row['token'] in fds:raise ValueError('duplicate oracle socket token')
            fds[row['token']]=row['fd']
        else:raise ValueError('unsupported oracle record')
    if len(set(tokens.values()))!=len(tokens) or set(tokens.values())!=set(fds):raise ValueError('incomplete oracle')
    nodes={n['id']:n for n in graph['nodes']};out={}
    for e in graph['edges']:out.setdefault(e['source'],[]).append(e['target'])
    roots=[n for n in nodes.values() if n['kind']=='request']
    if {n['rpc_id'] for n in roots}!=set(tokens):raise ValueError('graph/oracle request mismatch')
    checks=[];coverage=[]
    for root in roots:
        seen=set();stack=[root['id']]
        while stack:
            current=stack.pop()
            if current in seen:continue
            seen.add(current);stack.extend(out.get(current,[]))
        expected=fds[tokens[root['rpc_id']]]
        operations=[nodes[n] for n in seen if nodes[n]['kind']=='ring_operation']
        for operation in operations:checks.append(dict(rpc_id=root['rpc_id'],operation=operation['id'],
            expected_fd=expected,observed_fd=operation['target'],correct=operation['target']==expected))
        coverage.append(dict(rpc_id=root['rpc_id'],operations=len(operations)))
    return dict(checks=checks,requests=coverage,checked_links=len(checks),mismatches=sum(not x['correct'] for x in checks),
                covered_requests=sum(x['operations']>0 for x in coverage),limitations=[
                    'socket target matching validates ancestry consistency, not exclusive causality',
                    'shared socket tokens cannot distinguish requests with identical target descriptors',
                    'zero reachable operations does not prove absence of effects'])


def evaluate_shared_sequence(result,oracle,actions):
    tokens={row['token']:row['rpc_id'] for row in oracle if row['kind']=='request'}
    if len(actions)!=2*len(tokens) or not actions:raise ValueError('incomplete action sequence')
    seen=set();fd=actions[0]['fd']
    for i in range(0,len(actions),2):
        stop,start=actions[i:i+2]
        if stop['action']!='stop' or start['action']!='start' or stop['token']!=start['token']:
            raise ValueError('unexpected stop/start ordering')
        if stop['token'] not in tokens or stop['token'] in seen:raise ValueError('invalid action token')
        if any(x.get('turn')!=0 for x in [stop,start]):raise ValueError('actions crossed event-loop turn or missing turn evidence')
        if any(x['result']!=0 or x['fd']!=fd for x in [stop,start]):raise ValueError('failed or different-socket action')
        seen.add(stop['token'])
    survivor=tokens[actions[-1]['token']]
    mismatches=[row for row in result['requests'] if (row['operations']>0)!=(row['rpc_id']==survivor)]
    return dict(expected_surviving_request=survivor,mismatches=len(mismatches),failed_checks=mismatches,
                scope='single controlled synchronous stop/start batch; checks queue survival, not all request effects')


def score(run,graph=None):
    path=run/'socket-oracle.json'
    result=evaluate(build(run) if graph is None else graph,json.loads(path.read_text()))
    action_path=run/'watcher-action-oracle.json'
    if action_path.exists():
        result['shared_sequence']=evaluate_shared_sequence(result,json.loads(path.read_text()),json.loads(action_path.read_text()))
        result['mismatches']+=result['shared_sequence']['mismatches']
        result['action_oracle_sha256']=hashlib.sha256(action_path.read_bytes()).hexdigest()
    return dict(**result,oracle_sha256=hashlib.sha256(path.read_bytes()).hexdigest())

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('run',type=Path)
    result=score(p.parse_args().run);print(json.dumps(result,indent=2))
    if result['mismatches']:raise SystemExit(1)
