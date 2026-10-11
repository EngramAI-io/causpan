#!/usr/bin/env python3
"""Build a typed native-ring evidence graph; ancestry is not exclusive ownership."""
import argparse
import json
from pathlib import Path
import re
from native_preparation import report as preparation_report
from native_watcher_operations import report as watcher_report
from native_retry_ancestry import report as retry_report
from native_watcher_queue import report as queue_report
from native_marker_timeline import report as marker_report


def build(run):
    preparations=preparation_report(run);watchers=watcher_report(run);retries=retry_report(run)
    nodes={};edges=[]
    def node(identity,kind,**data):
        value=dict(id=identity,kind=kind,**data)
        if identity in nodes and nodes[identity]!=value:raise ValueError('conflicting graph identity')
        nodes[identity]=value
        return identity
    def edge(source,target,kind):edges.append(dict(source=source,target=target,kind=kind))
    for row in map(json.loads,(run/'request-map.jsonl').read_text().splitlines()):
        if row['kind']=='request':node('request:'+str(row['context']),'request',context=row['context'],rpc_id=row['rpc_id'])
    pending={};ring=None;completion_for={};submission=None;batch_index=-1
    submission_contexts=marker_report(run)['batches']
    for number,line in enumerate((run/'debugger.log').read_text().splitlines(),1):
        v={k:int(x) for k,x in re.findall(r'(\w+)=(-?\d+)',line)}
        if line.startswith('BATCH '):
            ring=v['fd'];batch_index+=1
            context=submission_contexts[batch_index]
            submission=node('enter:'+str(number),'io_uring_enter',line=number,ring_fd=ring,
                            sq_head=v['head'],sq_tail=v['tail'],tid=context['tid'],
                            execution_context=context['execution_context'])
        elif line.startswith('RETURN '):
            result=node('enter-return:'+str(number),'syscall_return',line=number,result=v['result'])
            edge(submission,result,'returned_as')
        elif line.startswith('SQE '):
            identity=node('sqe:'+str(number),'ring_operation',line=number,ring_fd=ring,**v)
            pending[(ring,v['user_data'])]=identity
            edge(identity,submission,'submitted_by')
        elif line.startswith('CQE '):
            source=pending.pop((ring,v['user_data']))
            target=node('cqe:'+str(number),'completion',line=number,ring_fd=ring,**v)
            completion_for[source]=target;edge(source,target,'completed_as')
    prep_for={}
    for item in preparations['joins']:
        source=node('prep:'+str(item['preparation']['line']),'preparation',**item['preparation'])
        target='sqe:'+str(item['sqe_line']);edge(source,target,'prepared_as');prep_for[item['sqe_line']]=source
    for link in watchers['links']:
        episode=link['queue_episode']
        if not episode:continue
        insertion=episode['insertion'];removal=episode['removal']
        source=node('enqueue:'+str(insertion['line']),'watcher_insertion',**insertion)
        target=node('dequeue:'+str(removal['line']),'watcher_removal',**removal)
        edge(source,target,'observed_queue_episode');edge(target,prep_for[link['sqe_line']],'poll_prepared')
        if insertion['context']:edge('request:'+str(insertion['context']),source,'executed_in_context')
        for update in episode.get('observed_updates',[]):
            update_id=node('update:'+str(update['line']),'watcher_update',**update)
            edge(update_id,target,'observed_update_while_queued')
            if update['context']:edge('request:'+str(update['context']),update_id,'executed_in_context')
    for episode in queue_report(run)['canceled']:
        insertion=episode['insertion'];cancellation=episode['cancellation']
        source=node('enqueue:'+str(insertion['line']),'watcher_insertion',**insertion)
        target=node('cancel:'+str(cancellation['line']),'watcher_cancellation',**cancellation)
        edge(source,target,'canceled_before_poll')
        if insertion['context']:edge('request:'+str(insertion['context']),source,'executed_in_context')
        if cancellation['context']:edge('request:'+str(cancellation['context']),target,'executed_in_context')
        for update in episode.get('observed_updates',[]):
            update_id=node('update:'+str(update['line']),'watcher_update',**update)
            edge(update_id,target,'canceled_before_poll')
            if update['context']:edge('request:'+str(update['context']),update_id,'executed_in_context')
    for retry in retries['retries']:
        source=completion_for['sqe:'+str(retry['source_sqe_line'])]
        edge(source,prep_for[retry['retry_sqe_line']],'triggered_retry')
    if any(e['source'] not in nodes or e['target'] not in nodes for e in edges):raise ValueError('dangling graph edge')
    return dict(schema='causpan.native-evidence.v1',nodes=list(nodes.values()),edges=edges,
                artifact_sha256=preparations['artifact_sha256'],
                limitations=['trusted intrusive binary-specific collector','queue coalescing and watcher lifetime gaps remain',
                             'request reachability denotes observed ancestry, not exclusive operation ownership',
                             'not yet merged into the strace attribution graph'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('run',type=Path)
    print(json.dumps(build(p.parse_args().run),indent=2))
