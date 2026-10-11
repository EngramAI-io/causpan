#!/usr/bin/env python3
"""Compare inferred resource ancestry against separately recorded client/socket tokens."""
import argparse
import hashlib
import json
from pathlib import Path
from native_resource_context import report


def score(run):
    inference=report(run)  # Oracle is deliberately excluded from inference.
    oracle_path=run/'socket-oracle.json'
    oracle=json.loads(oracle_path.read_text())
    requests={};sockets={}
    for row in oracle:
        dest=requests if row['kind']=='request' else sockets
        key=row['rpc_id'] if row['kind']=='request' else row['token']
        if key in dest:raise ValueError('duplicate oracle identity')
        dest[key]=row['token'] if row['kind']=='request' else row['fd']
    if len(set(requests.values()))!=len(requests) or set(requests.values())!=set(sockets):
        raise ValueError('incomplete oracle token matching')
    checked=[];covered=set()
    for ref in inference['references']:
        rpc=ref['resource_creation_rpc_id']
        if rpc is None:continue
        token=requests.get(rpc)
        expected=sockets.get(token)
        correct=expected is not None and ref['target_fd']==expected
        checked.append(dict(line=ref['line'],rpc_id=rpc,token=token,expected_fd=expected,
                            observed_fd=ref['target_fd'],correct=correct))
        if correct:covered.add(rpc)
    return dict(requests=len(requests),covered_requests=len(covered),checked_links=len(checked),
                mismatches=sum(not x['correct'] for x in checked),checks=checked,
                oracle_sha256=hashlib.sha256(oracle_path.read_bytes()).hexdigest(),
                limitations=['validates claimed client-socket creation ancestry only, not all kernel effects',
                             'numeric FD oracle cannot distinguish same-number incarnations within one request',
                             'workload records Node private socket handle FD at connect; not a production identity source'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('run',type=Path)
    result=score(p.parse_args().run);print(json.dumps(result,indent=2))
    if result['mismatches'] or result['covered_requests']!=result['requests']:raise SystemExit(1)
