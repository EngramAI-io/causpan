"""Scoped adapter for the hashed, one-request/one-ring C experiment helper.

Identity comes from the existing runtime/process context bridge. SQE/CQE fields
are trusted helper observations corroborated by traced writes, not raw kernel
memory decoding. This does not infer operations for arbitrary io_uring users.
"""
import hashlib
import json
import re
from ring_observations import join_observations


def _object(pairs):
    result={}
    for key,value in pairs:
        if key in result:
            raise ValueError('duplicate ring observation field')
        result[key]=value
    return result


def helper_graph(run, events):
    settings=json.loads((run/'run-config.json').read_text())
    if settings.get('scenario') != 'uring':
        return [], 0
    binary=settings['ring_binary']
    if hashlib.sha256(open(binary,'rb').read()).hexdigest() != settings['ring_binary_sha256']:
        raise ValueError('ring helper binary differs from captured build identity')
    helpers=set()
    for event in events:
        if event['syscall']=='execve' and event['return_value']==0:
            match=re.match(r'("(?:\\.|[^"\\])*")',event['args'])
            if match and json.loads(match[1])==binary:
                if event['pid'] in helpers:
                    raise ValueError('multiple helper executions under one PID are unsupported')
                helpers.add(event['pid'])
    graph=[]
    count=0
    for pid in sorted(helpers):
        local=[e for e in events if e['pid']==pid]
        setups=[e for e in local if e['syscall']=='io_uring_setup']
        enters=[e for e in local if e['syscall']=='io_uring_enter']
        if len(setups)!=1 or (setups[0]['return_value'] or 0)<=0 or len(enters)!=1:
            raise ValueError('helper must have exactly one successful ring setup and enter')
        enter=enters[0]
        if not enter['request_ids'] or enter['origin']!='process_inheritance':
            raise ValueError('ring helper lacks inherited request context')
        if int(re.match(r'\d+',enter['args'])[0])!=setups[0]['return_value']:
            raise ValueError('helper enter references another ring')
        records=[];sources={};submitted={};completed={}
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
            sources[event['source']]=event
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
        operations=join_observations(records)
        if enter['return_value']!=len(operations):
            raise ValueError('helper kernel submission count disagrees with observations')
        for operation in operations:
            identity=f'ring-operation:{pid}:{setups[0]["return_value"]}:{operation["user_data"]}'
            uid=operation['user_data']
            graph.append(dict(type='node',id=identity,kind='ring_operation',
                **operation,request_ids=enter['request_ids'],runtime_pid=pid,runtime_tid=enter['tid'],
                kernel_worker_tid=None,submit_evidence=submitted[uid],completion_evidence=completed[uid],
                syscall_evidence=enter['source'],scope='trusted_single_request_helper_single_ring'))
            for kind,source in [('ring_submitted',enter['source']),('ring_submission_observed',submitted[uid]),('ring_completion_observed',completed[uid])]:
                graph.append(dict(type='edge',source='syscall:'+source,target=identity,kind=kind,evidence=source))
            count+=1
    return graph,count
