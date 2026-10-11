import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from ring_helper import helper_graph


class RingHelperTests(unittest.TestCase):
    def test_context_and_trace_integrity_gates(self):
        with tempfile.TemporaryDirectory() as directory:
            run=Path(directory);binary=run/'helper';binary.write_bytes(b'fixture identity')
            (run/'run-config.json').write_text(json.dumps(dict(scenario='uring',ring_binary=str(binary),
                ring_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())))
            def event(source,syscall,args,result,start,end):
                return dict(source=source,syscall=syscall,args=args,return_value=result,
                    timestamp_ns=start,completion_ns=end,pid=20,tid=20,
                    request_ids=[9],origin='process_inheritance')
            sqe=dict(kind='sqe',user_data=101,opcode=23,fd=4,offset=0,length=7,flags=0)
            cqe=dict(kind='cqe',user_data=101,result=7,flags=0)
            def witness(source,row,start,end):
                text=json.dumps(row)+'\n'
                return event(source,'write',f'1<pipe:[1]>, {json.dumps(text)}, {len(text)}',len(text),start,end)
            rows=[event('exec','execve',json.dumps(str(binary))+', [], []',0,0,1),
                  event('setup','io_uring_setup','8, {flags=0}',3,2,3),
                  witness('sqe',sqe,4,5),event('enter','io_uring_enter','3, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0',1,6,7),
                  witness('cqe',cqe,8,9)]
            graph,count=helper_graph(run,rows)
            self.assertEqual(count,1)
            node=next(r for r in graph if r['type']=='node')
            self.assertEqual(node['request_ids'],[9]);self.assertIsNone(node['kernel_worker_tid'])
            mutations=[lambda r:r[1].update(args='8, {flags=IORING_SETUP_SQPOLL}'),lambda r:r.pop(),lambda r:r[2].update(return_value=1),
                       lambda r:r[2].update(request_ids=[10]),lambda r:r[3].update(request_ids=[]),
                       lambda r:r[2].update(completion_ns=7),lambda r:r[4].update(timestamp_ns=6),
                       lambda r:r[3].update(return_value=2),lambda r:r[3].update(args='4, 1, 1, 0, NULL, 0'),
                       lambda r:r.insert(1,copy.deepcopy(r[0]))]
            for mutate in mutations:
                changed=copy.deepcopy(rows);mutate(changed)
                with self.assertRaises(ValueError):helper_graph(run,changed)
            binary.write_bytes(b'changed build')
            with self.assertRaisesRegex(ValueError,'binary differs'):helper_graph(run,rows)
