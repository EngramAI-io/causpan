import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from attribute import attribute

class AttributionTests(unittest.TestCase):
    def fixture(self,run,drop=None,drop_both=False,network=False,inbound_ambiguous=False,shared_fd_table=False,copied_fd_table=False,exec_cloexec=False,exec_shared_cloexec=False):
        (run/'traces').mkdir()
        (run/'request-map.jsonl').write_text(json.dumps({'context':1,'rpc_id':'opaque-id','tool':'test'})+'\n')
        markers=[];lines={100:[],101:[],200:[],201:[],202:[]};clock=0
        def event(tid,text):
            nonlocal clock
            clock+=1;lines[tid].append(f'1.{clock:06d} {text}')
        def note(tid,kind,req=0,op=0):
            m=dict(csp=1,kind=kind,request=req,operation=op,pointer=0,tid=tid,status=0)
            if kind!=drop or not drop_both:markers.append(m)
            if kind==drop:return
            body=json.dumps(m)+'\n'
            event(tid,f'write(9<{run}/native-events.jsonl>, {json.dumps(body)}, {len(body)}) = {len(body)}')
        event(100,'clone(child_stack=NULL, flags=CLONE_THREAD|CLONE_VM) = 101')
        note(100,'INSTALL')
        note(100,'JS_CONTEXT',1)
        note(100,'SUBMIT',1,1)
        note(101,'WORK_ENTER',1,1)
        event(101,f'pwrite64(7<{run}/sandbox/shared>, "data", 4, 0) = 4')
        source=f'strace.101:{len(lines[101])}'
        note(101,'WORK_LEAVE')
        event(101,f'pwrite64(7<{run}/sandbox/shared>, "background", 10, 128) = 10')
        note(100,'DONE_ENTER',1,1)
        note(100,'COMPLETE',1,1)
        note(100,'DONE_LEAVE')
        if shared_fd_table:
            note(100,'JS_CONTEXT',0)
            event(100,'clone3({flags=0x400}, 88) = 200')
            note(200,'JS_CONTEXT',2)
            event(200,'socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 30')
            event(200,'connect(30<TCP:[127.0.0.1:41000->127.0.0.1:42000]>, {sa_family=AF_INET, sin_port=htons(42000), sin_addr=inet_addr("127.0.0.1")}, 16) = 0')
            note(200,'JS_CONTEXT',0)
            event(100,'read(30<TCP:[127.0.0.1:41000->127.0.0.1:42000]>, "shared-fd-token", 64) = 15')
        if copied_fd_table:
            note(100,'JS_CONTEXT',1)
            event(100,'socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 20')
            event(100,'connect(20<TCP:[127.0.0.1:41000->127.0.0.1:42000]>, {sa_family=AF_INET, sin_port=htons(42000), sin_addr=inet_addr("127.0.0.1")}, 16) = 0')
            note(100,'JS_CONTEXT',0)
            event(100,'clone3({flags=0}, 88) = 201')
            event(201,'close(20<TCP:[127.0.0.1:41000->127.0.0.1:42000]>) = 0')
            event(100,'read(20<TCP:[127.0.0.1:41000->127.0.0.1:42000]>, "copied-fd-token", 64) = 15')
        if exec_cloexec:
            note(100,'JS_CONTEXT',1)
            event(100,'socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 25')
            event(100,'connect(25<TCP:[127.0.0.1:41000->127.0.0.1:42000]>, {sa_family=AF_INET, sin_port=htons(42000), sin_addr=inet_addr("127.0.0.1")}, 16) = 0')
            note(100,'JS_CONTEXT',0)
            event(100,'close_range(25, 25, 4) = 0')
            event(100,'execve("/bin/true", ["true"], 0x0) = 0')
            event(100,'read(25</tmp/reused-regular-file>, "after-exec", 10) = 10')
        if exec_shared_cloexec:
            note(100,'JS_CONTEXT',1)
            event(100,'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 26')
            event(100,'connect(26<TCP:[127.0.0.1:41000->127.0.0.1:42000]>, {sa_family=AF_INET, sin_port=htons(42000), sin_addr=inet_addr("127.0.0.1")}, 16) = 0')
            note(100,'JS_CONTEXT',0)
            event(100,'clone3({flags=0x400}, 88) = 202')
            event(202,'execve("/bin/true", ["true"], 0x0) = 0')
            event(100,'read(26<TCP:[127.0.0.1:41000->127.0.0.1:42000]>, "parent-kept-fd", 64) = 15')
        if network:
            note(100,'JS_CONTEXT',1)
            event(100,'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 8')
            event(100,'connect(8<TCP:[127.0.0.1:41000->127.0.0.1:42000]>, {sa_family=AF_INET, sin_port=htons(42000), sin_addr=inet_addr("127.0.0.1")}, 16) = 0')
            event(100,'fcntl(8<TCP:[127.0.0.1:41000->127.0.0.1:42000]>, F_DUPFD_CLOEXEC, 0) = 12')
            event(100,'close(8<TCP:[127.0.0.1:41000->127.0.0.1:42000]>) = 0')
            note(100,'JS_CONTEXT',0)
            event(100,'read(12<TCP:[127.0.0.1:41000->127.0.0.1:42000]>, "reply-token", 64) = 11')
            event(100,'close(12<TCP:[127.0.0.1:41000->127.0.0.1:42000]>) = 0')
            note(100,'JS_CONTEXT',1)
            event(100,'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 8')
            event(100,'connect(8<TCP:[127.0.0.1:41000->127.0.0.1:42000]>, {sa_family=AF_INET, sin_port=htons(42000), sin_addr=inet_addr("127.0.0.1")}, 16) = 0')
            note(100,'JS_CONTEXT',0)
            event(100,'read(8<TCP:[127.0.0.1:41000->127.0.0.1:42000]>, "later-token", 64) = 11')
            note(100,'JS_CONTEXT',2)
            event(100,'write(8<TCP:[127.0.0.1:41000->127.0.0.1:42000]>, "second-token", 12) = 12')
            note(100,'JS_CONTEXT',0)
            event(100,'read(8<TCP:[127.0.0.1:41000->127.0.0.1:42000]>, "ambiguous-token", 15) = 15')
            event(100,'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 10')
            event(100,'accept4(10<TCP:[127.0.0.1:42000]>, NULL, NULL, SOCK_CLOEXEC) = 11<TCP:[127.0.0.1:42000->127.0.0.1:43000]>')
            note(100,'JS_CONTEXT',0)
            event(100,'read(11<TCP:[127.0.0.1:42000->127.0.0.1:43000]>, "response-token", 15) = 15')
            note(100,'JS_CONTEXT',1)
            event(100,'write(11<TCP:[127.0.0.1:42000->127.0.0.1:43000]>, "request-token", 14) = 14')
            if inbound_ambiguous:
                note(100,'JS_CONTEXT',2)
                event(100,'write(11<TCP:[127.0.0.1:42000->127.0.0.1:43000]>, "second-request", 14) = 14')
            note(100,'JS_CONTEXT',1)
            event(100,'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 15')
            event(100,'connect(15<TCP:[127.0.0.1:41000->127.0.0.1:42000]>, {sa_family=AF_INET, sin_port=htons(42000), sin_addr=inet_addr("127.0.0.1")}, 16) = 0')
            note(100,'JS_CONTEXT',0)
            event(100,'close_range(15, 15, 0) = 0')
            event(100,f'openat(AT_FDCWD, "{run}/sandbox/reused-by-file", O_RDONLY) = 15')
            event(100,f'read(15<{run}/sandbox/reused-by-file>, "file-token", 4) = 4')
        for tid,rows in lines.items():
            if rows:(run/f'traces/strace.{tid}').write_text('\n'.join(rows)+'\n')
        (run/'native-events.jsonl').write_text(''.join(json.dumps(m)+'\n' for m in markers))
        (run/'attribution.jsonl').write_text(json.dumps({'source':source,'oracle_request_id':'opaque-id'})+'\n')
    def invoke(self,run):
        with contextlib.redirect_stdout(io.StringIO()):return attribute(run)
    def test_binding_and_restore(self):
        with tempfile.TemporaryDirectory() as d:
            run=Path(d);self.fixture(run)
            report=self.invoke(run)
            self.assertTrue(report['valid'])
            writes=[r for r in map(json.loads,(run/'causal-attribution.jsonl').read_text().splitlines()) if r['syscall']=='pwrite64']
            self.assertEqual([r['request_id'] for r in writes],['opaque-id',None])
            self.assertEqual(writes[1]['attribution'],'no_request_context')
            graph=list(map(json.loads,(run/'provenance.jsonl').read_text().splitlines()))
            nodes={r['id'] for r in graph if r['type']=='node'}
            self.assertTrue(any(r.get('kind')=='wrote_to' for r in graph))
            for edge in (r for r in graph if r['type']=='edge'):
                self.assertIn(edge['source'],nodes);self.assertIn(edge['target'],nodes)
    def test_socket_lifecycle_binds_dedicated_and_marks_reuse_ambiguous(self):
        with tempfile.TemporaryDirectory() as d:
            run=Path(d);self.fixture(run,network=True)
            with (run/'request-map.jsonl').open('a') as stream:
                stream.write(json.dumps({'kind':'request','context':2,'rpc_id':'second','tool':'test'})+'\n')
            report=self.invoke(run)
            self.assertTrue(report['valid'],report['errors'])
            self.assertEqual(report['retroactive_socket_reads'],4)
            rows=list(map(json.loads,(run/'causal-attribution.jsonl').read_text().splitlines()))
            read=next(row for row in rows if row['syscall']=='read' and 'reply-token' in row['args'])
            self.assertEqual(read['request_ids'],['opaque-id'])
            self.assertEqual(read['origin'],'socket_lifecycle')
            self.assertEqual(read['attribution'],'bound')
            duplicate=next(row for row in rows if row['syscall']=='fcntl')
            self.assertEqual(duplicate['connection_id'],read['connection_id'])
            later=next(row for row in rows if row['syscall']=='read' and 'later-token' in row['args'])
            self.assertEqual(later['request_ids'],[])
            self.assertEqual(later['candidate_request_ids'],['opaque-id','second'])
            ambiguous=next(row for row in rows if row['syscall']=='read' and 'ambiguous-token' in row['args'])
            self.assertEqual(ambiguous['request_ids'],[])
            self.assertEqual(ambiguous['candidate_request_ids'],['opaque-id','second'])
            self.assertEqual(ambiguous['attribution'],'ambiguous_resource')
            graph=list(map(json.loads,(run/'provenance.jsonl').read_text().splitlines()))
            graph_nodes={row['id'] for row in graph if row['type']=='node'}
            for edge in (row for row in graph if row['type']=='edge'):
                self.assertIn(edge['source'],graph_nodes)
                self.assertIn(edge['target'],graph_nodes)
            self.assertTrue(any(edge.get('kind')=='connected' for edge in graph))
            self.assertTrue(any(edge.get('kind')=='socket_effect' for edge in graph))
            request_write=next(row for row in rows if row['syscall']=='write' and 'second-token' in row['args'])
            request_write_id='syscall:'+request_write['source']
            self.assertTrue(any(edge.get('kind')=='executed' and edge.get('target','').endswith(request_write_id) for edge in graph))
            self.assertTrue(any(edge.get('kind')=='socket_effect' and edge.get('target','').endswith(request_write_id) for edge in graph))
            ambiguous_id='syscall:'+ambiguous['source']
            self.assertTrue(any(node.get('id','').endswith(ambiguous_id) for node in graph))
            self.assertTrue(any(edge.get('kind')=='socket_effect' and edge.get('target','').endswith(ambiguous_id) for edge in graph))
            connections=[node['id'] for node in graph if node.get('kind')=='network_connection']
            self.assertEqual(len(connections),5)
            self.assertEqual(len(set(connections)),5)
            accepted=next(row for row in rows if row['syscall']=='read' and 'response-token' in row['args'])
            self.assertEqual(accepted['request_ids'],['opaque-id'])
            self.assertEqual(accepted['origin'],'socket_lifecycle')
            self.assertTrue(any(edge.get('kind')=='accepted_connection' for edge in graph))
            reused=next(row for row in rows if row['syscall']=='read' and 'file-token' in row['args'])
            self.assertIsNone(reused['connection_id'])
            self.assertEqual(reused['attribution'],'no_request_context')
    def test_earlier_accepted_socket_read_uses_candidate_set_after_reuse(self):
        with tempfile.TemporaryDirectory() as d:
            run=Path(d);self.fixture(run,network=True,inbound_ambiguous=True)
            with (run/'request-map.jsonl').open('a') as stream:
                stream.write(json.dumps({'kind':'request','context':2,'rpc_id':'second','tool':'test'})+'\n')
            report=self.invoke(run)
            self.assertEqual(report['retroactive_socket_reads'],4)
            rows=list(map(json.loads,(run/'causal-attribution.jsonl').read_text().splitlines()))
            read=next(row for row in rows if row['syscall']=='read' and 'response-token' in row['args'])
            self.assertEqual(read['request_ids'],[])
            self.assertEqual(read['candidate_request_ids'],['opaque-id','second'])
            self.assertEqual(read['attribution'],'ambiguous_resource')

    def test_clone_files_shares_socket_descriptor_table(self):
        with tempfile.TemporaryDirectory() as d:
            run=Path(d);self.fixture(run,shared_fd_table=True)
            with (run/'request-map.jsonl').open('a') as stream:
                stream.write(json.dumps({'kind':'request','context':2,'rpc_id':'child-request','tool':'test'})+'\n')
            report=self.invoke(run)
            self.assertTrue(report['valid'],report['errors'])
            rows=list(map(json.loads,(run/'causal-attribution.jsonl').read_text().splitlines()))
            child_connect=next(row for row in rows if row['syscall']=='connect' and '30<TCP:' in row['args'])
            parent_read=next(row for row in rows if row['syscall']=='read' and 'shared-fd-token' in row['args'])
            self.assertEqual(parent_read['connection_id'],child_connect['connection_id'])
            self.assertEqual(parent_read['request_ids'],['child-request'])
            self.assertEqual(parent_read['origin'],'socket_lifecycle')

    def test_clone_without_clone_files_copies_descriptor_table(self):
        with tempfile.TemporaryDirectory() as d:
            run=Path(d);self.fixture(run,copied_fd_table=True)
            report=self.invoke(run)
            self.assertTrue(report['valid'],report['errors'])
            rows=list(map(json.loads,(run/'causal-attribution.jsonl').read_text().splitlines()))
            parent_read=next(row for row in rows if row['syscall']=='read' and 'copied-fd-token' in row['args'])
            self.assertEqual(parent_read['request_ids'],['opaque-id'])
            self.assertEqual(parent_read['origin'],'socket_lifecycle')

    def test_close_range_cloexec_is_applied_at_successful_exec(self):
        with tempfile.TemporaryDirectory() as d:
            run=Path(d);self.fixture(run,exec_cloexec=True)
            report=self.invoke(run)
            self.assertTrue(report['valid'],report['errors'])
            rows=list(map(json.loads,(run/'causal-attribution.jsonl').read_text().splitlines()))
            after_exec=next(row for row in rows if row['syscall']=='read' and 'after-exec' in row['args'])
            self.assertIsNone(after_exec['connection_id'])
            self.assertEqual(after_exec['attribution'],'no_request_context')

    def test_exec_unshares_shared_table_and_keeps_parent_descriptor(self):
        with tempfile.TemporaryDirectory() as d:
            run=Path(d);self.fixture(run,exec_shared_cloexec=True)
            report=self.invoke(run)
            self.assertTrue(report['valid'],report['errors'])
            rows=list(map(json.loads,(run/'causal-attribution.jsonl').read_text().splitlines()))
            parent_read=next(row for row in rows if row['syscall']=='read' and 'parent-kept-fd' in row['args'])
            self.assertEqual(parent_read['request_ids'],['opaque-id'])
            self.assertEqual(parent_read['origin'],'socket_lifecycle')

    def test_unknown_exec_return_does_not_close_cloexec_socket(self):
        with tempfile.TemporaryDirectory() as d:
            run=Path(d);self.fixture(run,exec_cloexec=True)
            trace=run/'traces/strace.100'
            trace.write_text(trace.read_text().replace(
                'execve("/bin/true", ["true"], 0x0) = 0',
                'execve("/bin/true", ["true"], 0x0) = ? ERESTARTNOINTR (To be restarted)'
            ).replace('25</tmp/reused-regular-file>', '25<TCP:[127.0.0.1:41000->127.0.0.1:42000]>'))
            report=self.invoke(run)
            self.assertTrue(report['valid'],report['errors'])
            rows=list(map(json.loads,(run/'causal-attribution.jsonl').read_text().splitlines()))
            read=next(row for row in rows if row['syscall']=='read' and 'after-exec' in row['args'])
            self.assertIsNotNone(read['connection_id'])
            self.assertEqual(read['request_ids'],['opaque-id'])

    def test_thread_unsharing_does_not_close_peer_socket(self):
        for action in ('close_range', 'unshare'):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as d:
                run=Path(d);self.fixture(run,copied_fd_table=True)
                parent=run/'traces/strace.100'
                parent.write_text(parent.read_text().replace('clone3({flags=0}',
                    'clone3({flags=CLONE_FILES|CLONE_VM|CLONE_SIGHAND|CLONE_THREAD}'))
                child=run/'traces/strace.201'
                original=child.read_text()
                timestamp=original.split()[0]
                child.write_text(
                    f'{timestamp} close_range(20, 20, 2) = 0\n' if action=='close_range'
                    else f'{timestamp} unshare(0x400) = 0\n'+original)
                report=self.invoke(run)
                self.assertTrue(report['valid'],report['errors'])
                rows=list(map(json.loads,(run/'causal-attribution.jsonl').read_text().splitlines()))
                read=next(row for row in rows if 'copied-fd-token' in row['args'])
                self.assertEqual(read['request_ids'],['opaque-id'])
                self.assertIsNotNone(read['connection_id'])
    def test_malformed_rerun_cannot_leave_previous_valid_outputs(self):
        with tempfile.TemporaryDirectory() as d:
            run=Path(d);self.fixture(run);self.invoke(run)
            self.assertTrue((run/'provenance.jsonl').read_text())
            (run/'request-map.jsonl').write_text('{broken json')
            with self.assertRaises(ValueError):self.invoke(run)
            self.assertFalse(json.loads((run/'causal-report.json').read_text())['valid'])
            self.assertEqual((run/'provenance.jsonl').read_text(),'')
            self.assertEqual((run/'causal-attribution.jsonl').read_text(),'')
    def test_oracle_disagreement_invalidates_published_bindings(self):
        with tempfile.TemporaryDirectory() as d:
            run=Path(d);self.fixture(run)
            row=json.loads((run/'attribution.jsonl').read_text());row['oracle_request_id']='different-request'
            (run/'attribution.jsonl').write_text(json.dumps(row)+'\n')
            with self.assertRaises(RuntimeError):self.invoke(run)
            self.assertFalse(json.loads((run/'causal-report.json').read_text())['valid'])
            self.assertEqual((run/'provenance.jsonl').read_text(),'')
    def test_join_has_multiple_request_parents(self):
        with tempfile.TemporaryDirectory() as d:
            run=Path(d);self.fixture(run)
            (run/'request-map.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in [
                {'kind':'request','context':2,'rpc_id':'a','tool':'test'},
                {'kind':'request','context':3,'rpc_id':'b','tool':'test'},
                {'kind':'join','context':1,'parents':[2,3]}]))
            oracle=json.loads((run/'attribution.jsonl').read_text());oracle['oracle_request_id']=None
            (run/'attribution.jsonl').write_text(json.dumps(oracle)+'\n')
            report=self.invoke(run)
            self.assertEqual(report['joins'],1)
            row=next(r for r in map(json.loads,(run/'causal-attribution.jsonl').read_text().splitlines()) if r['syscall']=='pwrite64')
            self.assertEqual(row['request_ids'],['a','b'])
            self.assertIsNone(row['request_id'])
            self.assertEqual(row['attribution'],'multi_parent')
            graph=list(map(json.loads,(run/'provenance.jsonl').read_text().splitlines()))
            self.assertEqual(sum(r.get('kind')=='joined' for r in graph),2)
    def test_join_unknown_parent_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            run=Path(d);self.fixture(run)
            with (run/'request-map.jsonl').open('a') as stream:
                stream.write(json.dumps({'kind':'join','context':2,'parents':[999]})+'\n')
            with self.assertRaisesRegex(ValueError,"unobserved join parent"):self.invoke(run)
            self.assertFalse(json.loads((run/'causal-report.json').read_text())['valid'])
            self.assertEqual((run/'provenance.jsonl').read_text(),'')

    def test_missing_trace_marker_invalidates_entire_capture(self):
        with tempfile.TemporaryDirectory() as d:
            run=Path(d);self.fixture(run,drop='WORK_ENTER')
            with self.assertRaises(RuntimeError):self.invoke(run)
            self.assertFalse(json.loads((run/'causal-report.json').read_text())['valid'])
            self.assertEqual((run/'provenance.jsonl').read_text(),'')
            self.assertTrue(all(r['request_id'] is None for r in map(json.loads,(run/'causal-attribution.jsonl').read_text().splitlines())))
    def test_missing_execution_bracket_even_in_both_streams_is_detected(self):
        with tempfile.TemporaryDirectory() as d:
            run=Path(d);self.fixture(run,drop='WORK_ENTER',drop_both=True)
            with self.assertRaises(RuntimeError):self.invoke(run)
            report=json.loads((run/'causal-report.json').read_text())
            self.assertTrue(any('execution bracket' in e for e in report['errors']))

if __name__=='__main__':unittest.main()
