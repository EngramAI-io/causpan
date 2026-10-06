import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from attribute import attribute

class AttributionTests(unittest.TestCase):
    def fixture(self,run,drop=None,drop_both=False):
        (run/'traces').mkdir()
        (run/'request-map.jsonl').write_text(json.dumps({'context':1,'rpc_id':'opaque-id','tool':'test'})+'\n')
        markers=[];lines={100:[],101:[]};clock=0
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
        for tid,rows in lines.items():(run/f'traces/strace.{tid}').write_text('\n'.join(rows)+'\n')
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
            graph=list(map(json.loads,(run/'provenance.jsonl').read_text().splitlines()))
            nodes={r['id'] for r in graph if r['type']=='node'}
            self.assertTrue(any(r.get('kind')=='wrote_to' for r in graph))
            for edge in (r for r in graph if r['type']=='edge'):
                self.assertIn(edge['source'],nodes);self.assertIn(edge['target'],nodes)
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
            with self.assertRaises(RuntimeError):self.invoke(run)
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
