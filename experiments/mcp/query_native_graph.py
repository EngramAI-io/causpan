#!/usr/bin/env python3
"""Query hash-validated native request ancestry, including canceled queue episodes."""
import argparse
import hashlib
import json
from pathlib import Path


def query(run,rpc_id):
    manifest=json.loads((run/'manifest.json').read_text())
    if manifest['status']!='complete':raise ValueError('capture is not complete')
    path=run/'native-graph.json'
    if hashlib.sha256(path.read_bytes()).hexdigest()!=manifest['native_graph_sha256']:
        raise ValueError('graph hash mismatch')
    graph=json.loads(path.read_text())
    for name,digest in graph['artifact_sha256'].items():
        if Path(name).name!=name:raise ValueError('invalid artifact name')
        if hashlib.sha256((run/name).read_bytes()).hexdigest()!=digest:raise ValueError('capture artifact changed: '+name)
    nodes={n['id']:n for n in graph['nodes']}
    roots=[n['id'] for n in nodes.values() if n['kind']=='request' and n['rpc_id']==rpc_id]
    if len(roots)!=1:raise ValueError('request identity is missing or ambiguous')
    outgoing={}
    for edge in graph['edges']:outgoing.setdefault(edge['source'],[]).append(edge['target'])
    seen=set();stack=list(roots)
    while stack:
        current=stack.pop()
        if current in seen:continue
        seen.add(current);stack.extend(outgoing.get(current,[]))
    selected=[n for n in graph['nodes'] if n['id'] in seen]
    return dict(rpc_id=rpc_id,nodes=selected,edges=[e for e in graph['edges'] if e['source'] in seen and e['target'] in seen],
                ring_operations=sum(n['kind']=='ring_operation' for n in selected),
                canceled_episodes=sum(n['kind']=='watcher_cancellation' for n in selected),
                limitations=graph['limitations']+['no reachable ring operation does not imply no kernel effects'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('run',type=Path);p.add_argument('--rpc-id',required=True,type=json.loads)
    a=p.parse_args();print(json.dumps(query(a.run,a.rpc_id),indent=2))
