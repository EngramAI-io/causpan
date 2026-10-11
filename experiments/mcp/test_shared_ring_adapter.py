import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from shared_ring_adapter import shared_graph


class SharedRingTests(unittest.TestCase):
    def test_each_operation_uses_submission_context_not_batch_or_completion_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            run=Path(directory);binary=run/'helper';binary.write_bytes(b'fixture')
            (run/'run-config.json').write_text(json.dumps(dict(scenario='uring-shared',ring_binary=str(binary),
                ring_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())))
            def event(source,syscall,args,result,start,end,requests=None):
                return dict(source=source,syscall=syscall,args=args,return_value=result,pid=20,tid=20,
                    timestamp_ns=start,completion_ns=end,paths=[],request_ids=requests or [],
                    origin='ipc_worker' if requests else 'async_context',ipc_job='job:'+str(requests))
            records=[dict(kind='sqe',user_data=1,opcode=23,fd=4,offset=0,length=7,flags=0,batch=1),
                     dict(kind='sqe',user_data=2,opcode=23,fd=4,offset=512,length=7,flags=0,batch=1),
                     dict(kind='cqe',user_data=2,result=7,flags=0,batch=1),
                     dict(kind='cqe',user_data=1,result=7,flags=0,batch=1)]
            def witness(index,start,requests=None):
                text=json.dumps(records[index])+'\n'
                row=event('w'+str(index),'write',f'5<{run}/ring-observations.jsonl>, {json.dumps(text)}, {len(text)}',len(text),start,start+1,requests)
                row['paths']=[str(run/'ring-observations.jsonl')];return row
            rows=[event('exec','execve',json.dumps(str(binary))+', [], []',0,0,1),
                  event('setup','io_uring_setup','8, {flags=0}',3,2,3),
                  witness(0,4,[7]),witness(1,6,[8]),
                  event('enter','io_uring_enter','3, 2, 2, IORING_ENTER_GETEVENTS, NULL, 0',2,8,9),
                  witness(2,10),witness(3,12)]
            (run/'ring-observations.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in records))
            graph,count=shared_graph(run,rows,set())
            ops=[r for r in graph if r['type']=='node' and r['kind']=='ring_operation']
            self.assertEqual(count,2)
            self.assertEqual({r['user_data']:r['request_ids'] for r in ops},{1:[7],2:[8]})
            self.assertEqual({r['syscall_evidence'] for r in ops},{'enter'})
            mutations=[lambda r:r[1].update(args='8, {flags=IORING_SETUP_SQPOLL}'),lambda r:r.pop(),lambda r:r[2].update(request_ids=[]),
                       lambda r:r[2].update(origin='async_context'),
                       lambda r:r[4].update(request_ids=[7]),lambda r:r[5].update(request_ids=[8]),
                       lambda r:r[4].update(return_value=1),lambda r:r[5].update(timestamp_ns=8),
                       lambda r:r[2].update(return_value=1)]
            for mutate in mutations:
                changed=copy.deepcopy(rows);mutate(changed)
                with self.assertRaises(ValueError):shared_graph(run,changed,set())
            (run/'ring-observations.jsonl').write_text('corrupted')
            with self.assertRaisesRegex(ValueError,'sidecar differs'):shared_graph(run,rows,set())

            # The supported worker drains each batch before preparing the next.
            second=copy.deepcopy(rows[2:])
            second_records=[]
            for event in second:
                event['source']+='-batch2'
                event['timestamp_ns']+=20;event['completion_ns']+=20
                if event['syscall']=='write':
                    index=int(event['source'][1])
                    record=copy.deepcopy(records[index]);record['user_data']+=2;record['batch']=2
                    second_records.append(record)
                    text=json.dumps(record)+'\n'
                    event['args']=f'5<{run}/ring-observations.jsonl>, {json.dumps(text)}, {len(text)}'
                    event['return_value']=len(text)
            (run/'ring-observations.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in records+second_records))
            combined=rows+second
            self.assertEqual(shared_graph(run,combined,set())[1],4)
            overlapping=copy.deepcopy(combined);overlapping[len(rows)]['timestamp_ns']=11
            with self.assertRaisesRegex(ValueError,'previous batch completion'):
                shared_graph(run,overlapping,set())
            untimed=copy.deepcopy(combined);untimed[-1]['completion_ns']=None
            with self.assertRaisesRegex(ValueError,'CQE witness lacks completion timing'):
                shared_graph(run,untimed,set())
