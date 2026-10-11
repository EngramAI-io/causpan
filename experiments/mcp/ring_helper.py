"""Scoped adapter for the hashed, one-request/one-ring C experiment helper.

Identity comes from the existing runtime/process context bridge. SQE/CQE fields
are trusted helper observations corroborated by traced writes, not raw kernel
memory decoding. This does not infer operations for arbitrary io_uring users.
"""
import hashlib
import json
import re
from pathlib import Path
from ring_observations import join_observations, observed_file_resource, validate_waiting_enter, validate_scoped_ring


def _object(pairs):
    result={}
    for key,value in pairs:
        if key in result:
            raise ValueError('duplicate ring observation field')
        result[key]=value
    return result


def helper_graph(run, events, existing_ids=None):
    settings=json.loads((run/'run-config.json').read_text())
    if settings.get('scenario') not in {'uring','uring-memory','uring-reuse'}:
        return [], 0
    binary=settings['ring_binary']
    if hashlib.sha256(Path(binary).read_bytes()).hexdigest() != settings['ring_binary_sha256']:
        raise ValueError('ring helper binary differs from captured build identity')
    helpers=set()
    for event in events:
        if event['syscall']=='execve' and event['return_value']==0:
            match=re.match(r'("(?:\\.|[^"\\])*")',event['args'])
            if match and json.loads(match[1])==binary:
                if event['pid'] in helpers:
                    raise ValueError('multiple helper executions under one PID are unsupported')
                helpers.add(event['pid'])
    graph=[];seen=set(existing_ids or [])
    count=0
    for pid in sorted(helpers):
        collector_pid=pid
        collector=[e for e in events if e['pid']==pid]
        memory=settings.get('scenario')=='uring-memory'
        if memory:
            forks=[e for e in collector if e['syscall'] in {'clone','clone3','fork'} and (e['return_value'] or 0)>0]
            if len(forks)!=1:raise ValueError('memory collector requires one worker fork')
            pid=forks[0]['return_value']
        local=[e for e in events if e['pid']==pid]
        setups=[e for e in (collector if memory else local) if e['syscall']=='io_uring_setup']
        enters=[e for e in local if e['syscall']=='io_uring_enter']
        if len(setups)!=1 or (setups[0]['return_value'] is None or setups[0]['return_value']<0) or len(enters)!=1:
            raise ValueError('helper must have exactly one successful ring setup and enter')
        validate_scoped_ring(setups[0],local)
        enter=enters[0]
        if not enter['request_ids'] or enter['origin']!='process_inheritance':
            raise ValueError('ring helper lacks inherited request context')
        if int(re.match(r'\d+',enter['args'])[0])!=setups[0]['return_value']:
            raise ValueError('helper enter references another ring')
        if memory:
            for event in [setups[0],forks[0]]:
                if event['request_ids']!=enter['request_ids'] or event['origin']!='process_inheritance':
                    raise ValueError('collector lifecycle request context disagrees with worker')
            if setups[0].get('completion_ns') is None or forks[0].get('completion_ns') is None:
                raise ValueError('collector lifecycle timing missing')
            if not setups[0]['completion_ns']<=forks[0]['timestamp_ns']<=enter['timestamp_ns']:
                raise ValueError('collector lifecycle timing inverted')
            validate_scoped_ring(setups[0],[e for e in collector if e is not forks[0]])
        records=[];submitted={};completed={}
        for event in local:
            if event['syscall']!='write' or not re.match(r'1(?:<|,)',event['args']):
                continue
            match=re.search(r', ("(?:\\.|[^"\\])*"), (\d+)$',event['args'])
            if not match:
                raise ValueError('ring helper observation write cannot be decoded')
            data=json.loads(match[1])
            if len(data.encode())!=int(match[2]) or event['return_value']!=int(match[2]):
                raise ValueError('incomplete ring helper observation write')
            if not data.endswith('\n'):
                raise ValueError('split ring observation records unsupported')
            if event['request_ids']!=enter['request_ids']:
                raise ValueError('ring helper context changed during observations')
            for line in data.splitlines():
                record=json.loads(line,object_pairs_hook=_object)
                records.append(record)
                if record['kind']=='sqe':
                    if event.get('completion_ns') is None or event['completion_ns']>enter['timestamp_ns']:
                        raise ValueError('submission witness not observed before enter')
                    submitted[record['user_data']]=event['source']
                elif record['kind']=='cqe':
                    if enter.get('completion_ns') is None or event['timestamp_ns']<enter['completion_ns']:
                        raise ValueError('completion witness predates enter completion')
                    completed[record['user_data']]=event['source']
        memory_evidence=None
        if memory:
            from ring_memory_probe import decode
            metadata_text=""
            for event in local:
                if event['syscall']=='write' and re.match(r'2(?:<|,)',event['args']):
                    match=re.search(r', ("(?:\\.|[^"\\])*"), (\d+)$',event['args'])
                    if match:
                        text=json.loads(match[1])
                        if event['return_value']!=len(text.encode()):raise ValueError('short memory metadata witness')
                        if event['request_ids']!=enter['request_ids']:raise ValueError('metadata request context mismatch')
                        metadata_text+=text
            metadata=[json.loads(line) for line in metadata_text.splitlines()]
            if len(metadata)!=1:raise ValueError('memory metadata witness missing')
            buffers={};memory_evidence={}
            for name in ['sq.bin','sqes.bin','cq.bin']:
                writes=[e for e in collector if e['syscall']=='write' and any(Path(p).name==name for p in e['paths'])]
                if len(writes)!=1 or len(writes[0]['paths'])!=1:raise ValueError('snapshot write missing')
                witness=writes[0];path=Path(witness['paths'][0])
                if witness['request_ids']!=enter['request_ids']:raise ValueError('snapshot request context mismatch')
                if witness.get('completion_ns') is None or enter.get('completion_ns') is None:raise ValueError('snapshot timing missing')
                if path.is_symlink() or path.parent.is_symlink():raise ValueError('snapshot symlink unsupported')
                if path.parent.parent!=run or not path.parent.name.startswith('ring-memory-'):raise ValueError('snapshot outside capture')
                data=path.read_bytes()
                if witness['return_value']!=len(data):raise ValueError('short snapshot write')
                if name!='cq.bin' and witness['completion_ns']>enter['timestamp_ns']:raise ValueError('late SQ snapshot')
                if name=='cq.bin' and witness['timestamp_ns']<enter['completion_ns']:raise ValueError('early CQ snapshot')
                buffers[name]=data;memory_evidence[name]=dict(source=witness['source'],path=str(path),sha256=hashlib.sha256(data).hexdigest())
            decoded=decode(metadata[0],buffers['sq.bin'],buffers['sqes.bin'],buffers['cq.bin'])
            if decoded!=records:raise ValueError('raw ring memory disagrees with helper witnesses')
            records=decoded
        operations=join_observations(records)
        if memory:
            for operation in operations:operation['evidence']='parent_snapshot_of_inherited_shared_ring'

        validate_waiting_enter(enter,len(operations))
        if enter['return_value']!=len(operations):
            raise ValueError('helper kernel submission count disagrees with observations')
        for operation in operations:
            identity=f'ring-operation:{pid}:{setups[0]["return_value"]}:{operation["user_data"]}'
            uid=operation['user_data']
            if memory:
                for name,evidence in memory_evidence.items():
                    snapshot_id=f'ring-snapshot:{collector_pid}:{name}'
                    source='syscall:'+evidence['source']
                    if snapshot_id not in seen:
                        graph.append(dict(type='node',id=snapshot_id,kind='ring_snapshot',**evidence,collector_pid=collector_pid))
                        seen.add(snapshot_id)
                    if source not in seen:
                        event=next(e for e in collector if e['source']==evidence['source'])
                        graph.append(dict(type='node',id=source,kind='syscall',**{k:event.get(k) for k in ['timestamp_ns','duration_ns','completion_ns','pid','tid','syscall','paths','return_value']}))
                        seen.add(source)
                    edge=dict(type='edge',source=source,target=snapshot_id,kind='ring_snapshot_written',evidence=evidence['source'])
                    if edge not in graph:graph.append(edge)
                    graph.append(dict(type='edge',source=snapshot_id,target=identity,kind='ring_memory_observed',evidence=evidence['sha256']))

            resource=observed_file_resource(local,pid,operation['fd'],enter['timestamp_ns'])
            if resource['resource_evidence'] is not None:
                source='syscall:'+resource['resource_evidence']
                if source not in seen:
                    event=next(e for e in local if e['source']==resource['resource_evidence'])
                    graph.append(dict(type='node',id=source,kind='syscall',**{k:event.get(k) for k in ['timestamp_ns','duration_ns','completion_ns','pid','tid','syscall','paths','return_value']}))
                    seen.add(source)
                graph.append(dict(type='edge',source=source,target=identity,kind='ring_resource_observed',evidence=resource['resource_evidence']))
            graph.append(dict(type='node',id=identity,kind='ring_operation',
                **operation,**resource,memory_evidence=memory_evidence,collector_pid=collector_pid,request_ids=enter['request_ids'],runtime_pid=pid,runtime_tid=enter['tid'],
                kernel_worker_tid=None,submit_evidence=submitted[uid],completion_evidence=completed[uid],
                syscall_evidence=enter['source'],scope='trusted_single_request_helper_single_ring'))
            for kind,source in [('ring_submitted',enter['source']),('ring_submission_observed',submitted[uid]),('ring_completion_observed',completed[uid])]:
                graph.append(dict(type='edge',source='syscall:'+source,target=identity,kind=kind,evidence=source))
            count+=1
    return graph,count
