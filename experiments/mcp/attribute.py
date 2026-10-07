#!/usr/bin/env python3
"""Reconstruct causal context from ordered runtime transitions, never paths/timing windows."""
import argparse
from collections import Counter, defaultdict
import json
import hashlib
import uuid
from pathlib import Path
import re
from analyze import parse_traces, clone_has_flag

TRANSITIONS={'JS_CONTEXT','WORK_ENTER','WORK_LEAVE','DONE_ENTER','DONE_LEAVE'}

def marker(event, run):
    if event['syscall']!='write' or event['paths']!=[str(run/'native-events.jsonl')]: return None
    quoted=re.match(r'\d+<[^>]+>,\s*("(?:\\.|[^"\\])*")',event['args'])
    if not quoted: raise ValueError(f'truncated marker at {event["source"]}')
    data=json.loads(json.loads(quoted[1]))
    if data.get('csp')!=1 or data.get('tid')!=event['tid']:
        raise ValueError(f'invalid marker at {event["source"]}')
    return data

def fd_number(event):
    match=re.match(r'\s*(\d+)(?:<[^>]*>)?',event['args'])
    return int(match[1]) if match else None

def close_range_has_flag(args,flag):
    if flag in args:return True
    match=re.match(r'\s*\d+\s*,\s*\d+\s*,\s*(0x[0-9a-fA-F]+|\d+)',args)
    return bool(match and int(match[1],0)&{'CLOSE_RANGE_CLOEXEC':4,'CLOSE_RANGE_UNSHARE':2}[flag])

def _attribute(run):
    events,quality=parse_traces(run/'traces')
    raw_mapping=list(map(json.loads,(run/'request-map.jsonl').read_text().splitlines()))
    mapping={r['context']:r for r in raw_mapping}
    state={}
    operations={}
    inherited={}
    active_work=defaultdict(list)
    runtime_spans={}
    span_threads=defaultdict(set)
    seen=defaultdict(list)
    errors=[]
    roots={c:r for c,r in mapping.items() if r.get('kind','request')=='request'}
    owners={}
    for r in raw_mapping:
        context=r['context']
        if r.get('kind','request')=='request':owners[context]={context}
        elif r.get('kind')=='join':
            parents=r.get('parents',[])
            if not parents or any(parent not in owners for parent in parents):
                errors.append(f'unknown or cyclic join parent for context {context}');owners[context]=set()
            else:owners[context]=set().union(*(owners[parent] for parent in parents))
        else:errors.append(f'unknown context kind for {context}')
    def context_node(context):return ('request:' if context in roots else 'join:')+str(context)
    if len(raw_mapping)!=len(mapping) or any(type(c) is not int or c<=0 for c in mapping):
        errors.append('invalid or duplicate context identity')
    if (run/'tool-calls.jsonl').exists():
        calls=list(map(json.loads,(run/'tool-calls.jsonl').read_text().splitlines()))
        expected_calls=Counter((type(c['id']).__name__,c['id'],c['tool']) for c in calls)
        mapped_calls=Counter((type(r['rpc_id']).__name__,r['rpc_id'],r['tool']) for r in roots.values())
        if expected_calls!=mapped_calls:errors.append('dispatch mappings do not match observed MCP calls')
    tagged=[]
    graph=[]
    executed_syscalls=set()
    sockets={}
    close_on_exec=set()
    fd_tables={}
    socket_generation=0
    socket_nodes=set()
    socket_parent_edges=set()
    connections_by_id={}
    settings=json.loads((run/'run-config.json').read_text()) if (run/'run-config.json').exists() else {}
    session_id=settings.get('session_id',run.name)
    fd_table_serial=0
    def new_fd_table():
        nonlocal fd_table_serial
        fd_table_serial+=1
        return f'fdtable:{session_id}:{fd_table_serial}'
    def fd_table(pid):
        if pid not in fd_tables:fd_tables[pid]=new_fd_table()
        return fd_tables[pid]
    def copy_fd_table(table):
        copied=new_fd_table()
        for (table_id,number),owner in list(sockets.items()):
            if table_id==table:
                sockets[(copied,number)]=owner
                if (table_id,number) in close_on_exec:close_on_exec.add((copied,number))
        return copied
    for context,r in mapping.items():
        graph.append(dict(type='node',id=context_node(context),kind='mcp_request' if context in roots else 'causal_join',
                          **{k:v for k,v in r.items() if k!='kind'}))
        if context not in roots:
            for parent in r.get('parents',[]):
                graph.append(dict(type='edge',source=context_node(parent),target=context_node(context),kind='joined'))
    for event in events:
        note=marker(event,run)
        tid=event['tid']
        if note:
            seen[tid].append(note)
            kind=note['kind']; op=note['operation']; req=note['request']
            if req and req not in mapping: errors.append(f'unknown request context {req}')
            if kind=='SUBMIT':
                if op in operations: errors.append(f'duplicate operation {op}')
                operations[op]=dict(request=req,started=False,finished=False,completed=False,worker_tid=None)
                unit=note.get('unit','libuv_work')
                graph.append(dict(type='node',id=f'work:{op}',kind='execution_interval' if unit=='span_poll' else 'async_work',unit=unit,request_context=req))
                if unit=='span_poll':
                    span=note['pointer'];span_threads[(req,span)].add(tid)
                    if span not in runtime_spans:
                        runtime_spans[span]=req
                        graph.append(dict(type='node',id=f'task:{span}',kind='runtime_span',request_context=req))
                        if req:graph.append(dict(type='edge',source=context_node(req),target=f'task:{span}',kind='created_task'))
                    elif runtime_spans[span]!=req:errors.append(f'runtime span {span} changed identity')
                    graph.append(dict(type='edge',source=f'task:{span}',target=f'work:{op}',kind='polled'))
                elif req: graph.append(dict(type='edge',source=context_node(req),target=f'work:{op}',kind='submitted'))
            elif kind=='WORK_ENTER':
                work=operations.get(op)
                if not work or work['request']!=req or work['started']:
                    errors.append(f'invalid work entry {op}')
                else: work.update(started=True,worker_tid=tid)
                active_work[tid].append(op)
            elif kind=='WORK_LEAVE':
                if not active_work[tid]:errors.append(f'work leave without enter on TID {tid}')
                else:
                    finished=active_work[tid].pop()
                    if finished in operations:operations[finished]['finished']=True
            elif kind=='COMPLETE':
                work=operations.get(op)
                if not work or work['completed'] or work['request']!=req:
                    errors.append(f'invalid completion {op}')
                else: work.update(completed=True,status=note['status'])
            elif kind in {'INVARIANT_FAILURE','DUPLICATE_WORK'}:
                errors.append(kind)
            if kind in TRANSITIONS:
                state[tid]=dict(request=req,operation=op,origin='worker' if kind=='WORK_ENTER' else
                               'completion' if kind=='DONE_ENTER' else 'async_context',marker_source=event['source'])
            continue
        # Exclude instrumentation output itself from attributed effects.
        if any(path in {str(run/'request-map.jsonl'),str(run/'native-events.jsonl')} for path in event['paths']):
            continue
        context=state.get(tid,inherited.get(event['pid'],{}))
        request=context.get('request',0)
        fd=fd_number(event)
        table=fd_table(tid)
        key=(table,fd) if fd is not None else None
        socket_state=sockets.get(key) if key else None
        if event['syscall']=='socket' and event['return_value'] is not None and event['return_value']>=0:
            fd=event['return_value'];key=(table,fd)
            socket_generation+=1
            socket_state=dict(requests=set(),id=f'connection:{event["pid"]}:{fd}:{socket_generation}')
            sockets[key]=socket_state
            close_on_exec.discard(key)
            if 'SOCK_CLOEXEC' in event['args']:close_on_exec.add(key)
            connections_by_id[socket_state['id']]=socket_state
            if request:socket_state['requests'].update(owners.get(request,{request}))
        elif event['syscall'] in {'accept','accept4'} and event['return_value'] is not None and event['return_value']>=0:
            listener=sockets.get(key) if key else None
            fd=event['return_value'];key=(table,fd)
            socket_generation+=1
            socket_state=dict(requests=set(),id=f'connection:{event["pid"]}:{fd}:{socket_generation}')
            sockets[key]=socket_state
            close_on_exec.discard(key)
            if event['syscall']=='accept4' and 'SOCK_CLOEXEC' in event['args']:close_on_exec.add(key)
            connections_by_id[socket_state['id']]=socket_state
            if request:socket_state['requests'].update(owners.get(request,{request}))
            if listener:
                socket_nodes.add(socket_state['id'])
                graph.append(dict(type='node',id=socket_state['id'],kind='network_connection',pid=event['pid'],fd=fd))
                graph.append(dict(type='edge',source=listener['id'],target=socket_state['id'],kind='accepted_connection',evidence=event['source']))
                graph.append(dict(type='edge',source='syscall:'+event['source'],target=socket_state['id'],kind='accepted'))
        elif event['syscall']=='connect' and fd is not None:
            if socket_state is None:
                socket_generation+=1
                socket_state=dict(requests=set(),id=f'connection:{event["pid"]}:{fd}:{socket_generation}')
                sockets[key]=socket_state
                connections_by_id[socket_state['id']]=socket_state
            if request:socket_state['requests'].update(owners.get(request,{request}))
        elif event['syscall'] in {'dup','dup2','dup3'} and fd is not None and event['return_value'] is not None and event['return_value']>=0:
            destination=(table,event['return_value'])
            if not (event['syscall'] in {'dup2','dup3'} and fd==event['return_value']):
                sockets.pop(destination,None)
                close_on_exec.discard(destination)
                if socket_state:sockets[destination]=socket_state
                if socket_state and event['syscall']=='dup3' and 'O_CLOEXEC' in event['args']:
                    close_on_exec.add(destination)
        elif event['syscall']=='fcntl' and fd is not None and event['return_value'] is not None and event['return_value']>=0:
            if 'F_DUPFD' in event['args']:
                destination=(table,event['return_value'])
                sockets.pop(destination,None)
                close_on_exec.discard(destination)
                if socket_state:sockets[destination]=socket_state
                if socket_state and 'F_DUPFD_CLOEXEC' in event['args']:
                    close_on_exec.add(destination)
            elif 'F_SETFD' in event['args']:
                if 'FD_CLOEXEC' in event['args']:close_on_exec.add(key)
                else:close_on_exec.discard(key)
        elif event['syscall']=='close_range' and event['return_value']==0:
            if close_range_has_flag(event['args'],'CLOSE_RANGE_UNSHARE'):
                table=copy_fd_table(table)
                fd_tables[tid]=table
            descriptor_range=re.match(r'\s*(\d+)\s*,\s*(\d+)',event['args'])
            if descriptor_range:
                first,last=map(int,descriptor_range.groups())
                descriptors=[item for item in sockets if item[0]==table and first<=item[1]<=last]
                if close_range_has_flag(event['args'],'CLOSE_RANGE_CLOEXEC'):
                    close_on_exec.update(descriptors)
                else:
                    for descriptor in descriptors:
                        sockets.pop(descriptor,None)
                        close_on_exec.discard(descriptor)
            socket_state=None
        elif event['syscall'] in {'clone','clone3','fork','vfork'} and (event['return_value'] or 0)>0:
            child=event['return_value']
            if clone_has_flag(event['args'],'CLONE_FILES'):
                fd_tables[child]=table
            else:
                fd_tables[child]=copy_fd_table(table)
        elif event['syscall']=='unshare' and event['return_value']==0:
            flags=event['args'].strip()
            if 'CLONE_FILES' in flags or (re.fullmatch(r'0x[0-9a-fA-F]+|\d+',flags) and int(flags,0)&0x400):
                fd_tables[tid]=copy_fd_table(table)
        elif event['syscall'] in {'execve','execveat'} and event['return_value']==0:
            table=copy_fd_table(table)
            fd_tables[tid]=table
            for descriptor in [item for item in close_on_exec if item[0]==table]:
                sockets.pop(descriptor,None)
                close_on_exec.discard(descriptor)
        if socket_state and event['syscall'] in {'read','readv','recvfrom','recvmsg','write','writev','sendto','sendmsg'}:
            socket_state['requests'].update(owners.get(request,{request}) if request else ())
        if socket_state and event['syscall']=='close' and key and event['return_value']==0:
            sockets.pop(key,None)
            close_on_exec.discard(key)
        if socket_state and socket_state['id'] not in socket_nodes:
            socket_nodes.add(socket_state['id'])
            graph.append(dict(type='node',id=socket_state['id'],kind='network_connection',pid=event['pid'],fd=fd))
        if socket_state:
            for parent in sorted(socket_state['requests']):
                relation=(parent,socket_state['id'])
                if relation not in socket_parent_edges:
                    socket_parent_edges.add(relation)
                    graph.append(dict(type='edge',source=context_node(parent),target=socket_state['id'],kind='connected',evidence=event['source']))
        if socket_state:
            if event['syscall'] in {'read','readv','recvfrom','recvmsg','write','writev','sendto','sendmsg'}:
                graph.append(dict(type='edge',source=socket_state['id'],target='syscall:'+event['source'],kind='socket_effect',evidence=event['source']))
            if not request and len(socket_state['requests'])==1 and event['syscall'] in {'read','readv','recvfrom','recvmsg'}:
                request=next(iter(socket_state['requests']))
                context=dict(request=request,operation=0,origin='socket_lifecycle',marker_source=session_id+':'+socket_state['id'])
        if event['syscall'] in {'clone','clone3','fork','vfork'} and (event['return_value'] or 0)>0 and not clone_has_flag(event['args'],'CLONE_THREAD'):
            child=event['return_value']
            inherited[child]=dict(request=context.get('request',0),operation=0,origin='process_inheritance',marker_source=event['source'])
            graph.append(dict(type='node',id=f'process:{child}',kind='child_process',pid=child))
            if context.get('request'):
                graph.append(dict(type='edge',source=context_node(context['request']),target=f'process:{child}',kind='spawned',evidence=event['source']))
        request=request or context.get('request',0)
        request_ids=[roots[parent]['rpc_id'] for parent in sorted(owners.get(request,set()))]
        candidate_ids=[]
        if socket_state and len(socket_state['requests'])>1 and not context.get('request'):
            candidate_ids=[roots[parent]['rpc_id'] for parent in sorted(socket_state['requests'])]
        row=dict(**event,context=request,request_ids=request_ids,request_id=request_ids[0] if len(request_ids)==1 else None,
                 operation=context.get('operation',0),origin=context.get('origin','unobserved'),
                 context_evidence=context.get('marker_source'),
                 connection_id=socket_state['id'] if socket_state else None,
                 candidate_request_ids=candidate_ids,
                 attribution='ambiguous_resource' if candidate_ids else 'multi_parent' if len(request_ids)>1 else 'bound' if request else 'no_request_context' if context.get('request')==0 else 'unknown')
        tagged.append(row)
        if request or socket_state:
            event_id='syscall:'+event['source']
            graph.append(dict(type='node',id=event_id,kind='syscall',timestamp_ns=event['timestamp_ns'],
                              pid=event['pid'],tid=tid,syscall=event['syscall'],paths=event['paths'],
                              return_value=event['return_value']))
            if request and event_id not in executed_syscalls:
                parent=f'process:{event["pid"]}' if row['origin']=='process_inheritance' else f'work:{row["operation"]}' if row['operation'] else context_node(request)
                graph.append(dict(type='edge',source=parent,target=event_id,kind='executed',
                                  evidence=row['context_evidence']))
                executed_syscalls.add(event_id)
    # A request-scoped effect later on the same accepted connection can provide
    # ownership evidence for an earlier unscoped socket read. Shared connections
    # stay candidate sets, since the runtime trace does not identify stream IDs.
    retroactive=0
    for row in tagged:
        connection_id=row.get('connection_id')
        if not connection_id or row['syscall'] not in {'read','readv','recvfrom','recvmsg'}:
            continue
        if row['context'] or row['attribution'] not in {'no_request_context','unknown'}:
            continue
        connection=connections_by_id.get(connection_id)
        request_contexts=sorted(connection['requests']) if connection else []
        if not request_contexts:
            continue
        request_ids=[roots[context]['rpc_id'] for context in request_contexts]
        row['context_evidence']=session_id+':'+connection_id
        row['origin']='socket_lifecycle'
        retroactive+=1
        if len(request_contexts)==1:
            row['context']=request_contexts[0]
            row['request_ids']=request_ids
            row['request_id']=request_ids[0]
            row['attribution']='bound'
        else:
            row['request_ids']=[]
            row['request_id']=None
            row['candidate_request_ids']=request_ids
            row['attribution']='ambiguous_resource'
    for row in tagged:
        if row.get('connection_id'):
            row['connection_id']=session_id+':'+row['connection_id']
    # An independent copy of every marker must match the ordered per-thread trace.
    expected=defaultdict(list)
    for note in map(json.loads,(run/'native-events.jsonl').read_text().splitlines()):
        expected[note['tid']].append(note)
    if dict(expected)!=dict(seen): errors.append('marker stream differs from native log (capture loss or corruption)')
    for key in ['unparsed','orphan_resumed','incomplete_at_eof','non_timestamp_lines']:
        if quality.get(key): errors.append(f'parser quality {key}={quality[key]}')
    for op,work in operations.items():
        if work.get('status')==0 and not (work['started'] and work['finished']):errors.append(f'operation {op} completed without observed execution bracket')
        if work.get('status')==-125 and work['started']:errors.append(f'cancelled operation {op} was executed')
    if any(active_work.values()):errors.append('unclosed worker execution context')
    unfinished=[op for op,w in operations.items() if not w['completed']]
    if unfinished: errors.append(f'{len(unfinished)} operations lack completion')
    # Evaluation sidecar is consulted only after inference, and never changes assignments.
    oracle={r['source']:r for r in map(json.loads,(run/'attribution.jsonl').read_text().splitlines())}
    selected=[r for r in tagged if r['source'] in oracle]
    score=Counter()
    per_request=Counter()
    for event in selected:
        truth=oracle[event['source']]['oracle_request_id']
        score['events']+=1
        score[event['attribution']]+=1
        for request_id in event['request_ids']:per_request[str(request_id)]+=1
        if truth is not None:
            score['oracle_labelled']+=1
            score['oracle_correct' if event['request_id']==truth else 'oracle_wrong']+=1
    if score['oracle_wrong']:errors.append(f'{score["oracle_wrong"]} independent path-oracle disagreements')
    report=dict(valid=not errors,errors=errors,attribution_model='causal-context-v2',requests=len(roots),joins=len(mapping)-len(roots),operations=len(operations),
                operations_started=sum(w['started'] for w in operations.values()),
                operations_cancelled=sum(w.get('status')==-125 for w in operations.values()),
                inherited_processes=len(inherited),runtime_spans=len(runtime_spans),
                retroactive_socket_reads=retroactive,
                migrating_request_spans=sum(req!=0 and len(tids)>1 for (req,span),tids in span_threads.items()),
                markers=sum(map(len,seen.values())),parser=quality,
                all_event_status=dict(Counter(e['attribution'] for e in tagged)),
                fixture_score=dict(score),fixture_events_per_request=dict(per_request))
    if errors:
        # Fail closed: retain tentative diagnostics but never publish them as valid bindings.
        for row in tagged:
            row['attribution']='invalid_capture';row['request_id']=None;row['request_ids']=[];row['context']=None
        graph=[]
    def write(name,rows): (run/name).write_text(''.join(json.dumps(r)+'\n' for r in rows))
    write('causal-attribution.jsonl',tagged)
    resources={}
    for node in list(graph):
        if node.get('kind')!='syscall':continue
        for path in node['paths']:
            rid='resource:'+str(len(resources)) if path not in resources else resources[path]
            if path not in resources:
                resources[path]=rid
                graph.append(dict(type='node',id=rid,kind='observed_resource',name=path,identity='pathname_or_fd_annotation'))
            syscall=node['syscall'];success=node['return_value'] is not None and node['return_value']>=0
            kind='read_from' if syscall in {'read','pread64','readv'} and success else 'wrote_to' if syscall in {'write','pwrite64','writev'} and success else 'referenced' if success else 'attempted_access'
            graph.append(dict(type='edge',source=node['id'],target=rid,kind=kind,semantics='resource_observation_not_data_dependency'))
    for record in graph:
        for field in ['id','source','target']:
            if field in record:record[field]=session_id+':'+record[field]
        record['session_id']=session_id
    write('provenance.jsonl',graph)
    report['analysis_id']=uuid.uuid4().hex
    report['output_sha256']={name:hashlib.sha256((run/name).read_bytes()).hexdigest() for name in ['causal-attribution.jsonl','provenance.jsonl']}
    temporary=run/'causal-report.json.tmp'
    temporary.write_text(json.dumps(report,indent=2)+'\n')
    temporary.replace(run/'causal-report.json')
    print(json.dumps(report,indent=2))
    if errors: raise RuntimeError('; '.join(errors))
    if score['oracle_wrong']: raise RuntimeError(f'{score["oracle_wrong"]} oracle disagreements')
    return report

def attribute(run):
    # Invalidate earlier results before parsing, including when the new input is malformed.
    # Publish the final valid report only after both output artifacts are complete.
    report_path=run/'causal-report.json'
    report_path.write_text(json.dumps({'valid':False,'errors':['analysis in progress']})+'\n')
    (run/'causal-attribution.jsonl').write_text('')
    (run/'provenance.jsonl').write_text('')
    try:
        return _attribute(run)
    except Exception as error:
        report=json.loads(report_path.read_text())
        report['valid']=False
        if str(error) not in report.setdefault('errors',[]):report['errors'].append(str(error))
        (run/'provenance.jsonl').write_text('')
        (run/'causal-attribution.jsonl').write_text('')
        report.pop('output_sha256',None)
        report_path.write_text(json.dumps(report,indent=2)+'\n')
        raise

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('run',type=Path)
    attribute(p.parse_args().run.resolve())
