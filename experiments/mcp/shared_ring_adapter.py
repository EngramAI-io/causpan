"""Trusted per-SQE context adapter for one persistent, shared experimental ring."""
import hashlib
import json
from pathlib import Path
import re
from ring_observations import join_observations, observed_file_resource, validate_waiting_enter, validate_scoped_ring
from ring_helper import _object


def shared_graph(run, events, existing_ids):
    settings=json.loads((run/'run-config.json').read_text())
    if settings.get('scenario')!='uring-shared':return [],0
    binary=settings['ring_binary']
    if hashlib.sha256(Path(binary).read_bytes()).hexdigest()!=settings['ring_binary_sha256']:
        raise ValueError('shared ring binary identity mismatch')
    helpers=[]
    for event in events:
        if event['syscall']=='execve' and event['return_value']==0:
            match=re.match(r'("(?:\\.|[^"\\])*")',event['args'])
            if match and json.loads(match[1])==binary:helpers.append(event['pid'])
    if len(helpers)!=1:raise ValueError('shared adapter requires one observed persistent worker')
    pid=helpers[0];local=[e for e in events if e['pid']==pid]
    setups=[e for e in local if e['syscall']=='io_uring_setup']
    if len(setups)!=1 or setups[0]['return_value'] is None or setups[0]['return_value']<0:
        raise ValueError('shared adapter requires one successful ring setup')
    validate_scoped_ring(setups[0],local)
    enters=[e for e in local if e['syscall']=='io_uring_enter']
    records=[];witnesses={};groups={};raw=b''
    for event in local:
        if event['syscall']!='write' or event['paths']!=[str(run/'ring-observations.jsonl')]:continue
        match=re.search(r', ("(?:\\.|[^"\\])*"), (\d+)$',event['args'])
        if not match:raise ValueError('shared ring observation cannot be decoded')
        data=json.loads(match[1]);encoded=data.encode()
        if len(encoded)!=int(match[2]) or event['return_value']!=len(encoded) or not data.endswith('\n'):
            raise ValueError('incomplete shared ring observation write')
        raw+=encoded
        for line in data.splitlines():
            row=json.loads(line,object_pairs_hook=_object)
            if not isinstance(row,dict):raise ValueError('non-object ring observation')
            batch=row.get('batch')
            if type(batch) is not int or batch<1:raise ValueError('invalid ring batch identity')
            key=(row.get('kind'),row.get('user_data'))
            if key in witnesses:raise ValueError('duplicate ring observation identity')
            witnesses[key]=event;records.append(row);groups.setdefault(batch,[]).append(row)
    if raw!=(run/'ring-observations.jsonl').read_bytes():raise ValueError('shared ring sidecar differs from trace')
    operations=join_observations(records)
    if sorted(groups)!=list(range(1,len(enters)+1)):raise ValueError('ring batch/enter sequence mismatch')
    batch_by_id={r['user_data']:r['batch'] for r in records if r['kind']=='sqe'}
    enters_by_id={}
    previous_completion=setups[0].get('completion_ns')
    if previous_completion is None:raise ValueError('ring setup lacks completion timing')
    for batch,enter in enumerate(enters,1):
        group=groups[batch];sqes=[r for r in group if r['kind']=='sqe'];cqes=[r for r in group if r['kind']=='cqe']
        if not sqes or len(sqes)!=len(cqes) or enter['return_value']!=len(sqes):
            raise ValueError('ring batch kernel submission count mismatch')
        if validate_waiting_enter(enter,len(sqes))!=setups[0]['return_value']:
            raise ValueError('batch submitted to a different ring')
        if enter['request_ids']:raise ValueError('shared batch unexpectedly has a single execution owner')
        for row in sqes:
            witness=witnesses[('sqe',row['user_data'])]
            if witness['origin']!='ipc_worker' or not witness.get('ipc_job') or len(witness['request_ids'])!=1:
                raise ValueError('submission lacks unique verified IPC context')
            if witness['timestamp_ns']<previous_completion:
                raise ValueError('SQE preparation overlaps setup or previous batch completion')
            if witness.get('completion_ns') is None or witness['completion_ns']>enter['timestamp_ns']:
                raise ValueError('SQE witness follows batch submission')
            enters_by_id[row['user_data']]=enter
        for row in cqes:
            witness=witnesses[('cqe',row['user_data'])]
            if batch_by_id.get(row['user_data'])!=batch:raise ValueError('completion crossed batch identity')
            if enter.get('completion_ns') is None or witness['timestamp_ns']<enter['completion_ns']:
                raise ValueError('CQE witness predates batch completion')
            if witness['request_ids']:raise ValueError('completion dispatcher context leaked')
            if witness.get('completion_ns') is None:raise ValueError('CQE witness lacks completion timing')
        previous_completion=max(witnesses[('cqe',row['user_data'])]['completion_ns'] for row in cqes)
    graph=[];seen=set(existing_ids)
    for operation in operations:
        uid=operation['user_data'];submission=witnesses[('sqe',uid)];completion=witnesses[('cqe',uid)];enter=enters_by_id[uid]
        resource=observed_file_resource(local,pid,operation['fd'],enter['timestamp_ns'])
        evidence_events=[submission,completion,enter]
        if resource['resource_evidence'] is not None:
            evidence_events.append(next(e for e in local if e['source']==resource['resource_evidence']))
        for event in evidence_events:
            identity='syscall:'+event['source']
            if identity not in seen:
                graph.append(dict(type='node',id=identity,kind='syscall',**{k:event.get(k) for k in ['timestamp_ns','duration_ns','completion_ns','pid','tid','syscall','paths','return_value']}))
                seen.add(identity)
        identity=f'ring-operation:{pid}:{setups[0]["return_value"]}:{uid}'
        graph.append(dict(type='node',id=identity,kind='ring_operation',**operation,**resource,
            request_ids=submission['request_ids'],runtime_pid=pid,runtime_tid=submission['tid'],kernel_worker_tid=None,
            submit_evidence=submission['source'],completion_evidence=completion['source'],syscall_evidence=enter['source'],
            ipc_job=submission['ipc_job'],batch=batch_by_id[uid],scope='trusted_persistent_shared_ring_per_sqe_context'))
        if resource['resource_evidence'] is not None:
            graph.append(dict(type='edge',source='syscall:'+resource['resource_evidence'],target=identity,kind='ring_resource_observed',evidence=resource['resource_evidence']))
        for kind,event in [('ring_submitted',enter),('ring_submission_observed',submission),('ring_completion_observed',completion)]:
            graph.append(dict(type='edge',source='syscall:'+event['source'],target=identity,kind=kind,evidence=event['source']))
    return graph,len(operations)
