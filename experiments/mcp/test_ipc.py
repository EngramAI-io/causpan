"""Handoff integrity tests with matching log/trace copies (not just log corruption)."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from attribute import attribute


class IpcTests(unittest.TestCase):
    def check(self, mutation=None, two_dispatchers=False, cancelled=False, descendants=False, relay=False):
        with tempfile.TemporaryDirectory() as directory:
            run=Path(directory)
            (run/'traces').mkdir()
            (run/'request-map.jsonl').write_text(''.join(json.dumps(dict(context=c,rpc_id=c,tool='worker'))+'\n' for c in [1,2]))
            (run/'attribution.jsonl').write_text('')
            if mutation=='zero_context':
                (run/'run-config.json').write_text(json.dumps({'scenario':'worker-unscoped'}))
            notes=[];lines={100:[],200:[],300:[],400:[]};clock=0
            def event(tid,body):
                nonlocal clock
                clock+=1
                lines[tid].append(f'1.{clock:06d} {body}\n')
            def mark(tid,kind,request=1,job='dispatcher-1/job-1'):
                note=dict(csp=1,kind=kind,request=request,operation=0,pointer=0,tid=tid,status=0,job=job)
                notes.append(note)
                body=json.dumps(note)+'\n'
                result=-1 if mutation=='failed_marker_write' and kind=='IPC_ENTER' else len(body)-1 if mutation=='short_marker_write' and kind=='IPC_ENTER' else len(body)
                event(tid,f'write(9<{run}/native-events.jsonl>, {json.dumps(body)}, {len(body)}) = {result}')
            if mutation!='unobserved_sender':
                mark(100,'JS_CONTEXT',2 if mutation=='wrong_sender' else 1)
            if mutation!='missing_send':mark(100,'IPC_SEND')
            if mutation=='duplicate_send':mark(100,'IPC_SEND')
            if cancelled:
                mark(200,'IPC_CANCEL')
            else:
                if mutation=='cancel_then_execute':mark(200,'IPC_CANCEL')
                mark(200,'IPC_ENTER',request=0 if mutation=='zero_context' else 2 if mutation=='wrong_context' else 1)
                if mutation=='cancel_after_start':mark(200,'IPC_CANCEL')
                if mutation=='duplicate_enter':mark(200,'IPC_ENTER')
                if mutation=='context_switch':mark(200,'JS_CONTEXT',2)
                event(200,f'pwrite64(8<{run}/data>, "x", 1, 0) = 1')
                if relay:
                    mark(200,'IPC_SEND',job='relay/1')
                    mark(300,'IPC_ENTER',job='relay/1')
                    event(300,f'pwrite64(8<{run}/data>, \"r\", 1, 256) = 1')
                    mark(300,'IPC_LEAVE',job='relay/1')
                if descendants:
                    event(200,'clone(child_stack=NULL, flags=SIGCHLD) = 300')
                    event(300,'clone(child_stack=NULL, flags=SIGCHLD) = 400')
                    event(400,f'pwrite64(8<{run}/data>, \"g\", 1, 256) = 1')
                if mutation=='context_switch':mark(200,'JS_CONTEXT',1)
                if mutation!='missing_leave':mark(100 if mutation=='wrong_thread' else 200,'IPC_LEAVE')
                if mutation=='duplicate_leave':mark(200,'IPC_LEAVE')
            event(200,f'pwrite64(8<{run}/data>, "b", 1, 128) = 1')
            if two_dispatchers:
                mark(300,'JS_CONTEXT',2)
                mark(300,'IPC_SEND',request=2,job='dispatcher-2/job-1')
                mark(400,'IPC_ENTER',request=2,job='dispatcher-2/job-1')
                event(400,f'pwrite64(8<{run}/data>, \"y\", 1, 256) = 1')
                mark(400,'IPC_LEAVE',request=2,job='dispatcher-2/job-1')
            (run/'native-events.jsonl').write_text(''.join(json.dumps(n)+'\n' for n in notes))
            for tid,entries in lines.items():(run/'traces'/f'strace.{tid}').write_text(''.join(entries))
            with contextlib.redirect_stdout(io.StringIO()):
                try:attribute(run)
                except (RuntimeError,ValueError):pass
            report=json.loads((run/'causal-report.json').read_text())
            rows=[json.loads(x) for x in (run/'causal-attribution.jsonl').read_text().splitlines()]
            if mutation:
                self.assertFalse(report['valid'],mutation)
                self.assertEqual((run/'provenance.jsonl').read_text(),'')
                self.assertTrue(all(not r['request_ids'] for r in rows))
            else:
                self.assertTrue(report['valid'],report)
                if descendants or relay:
                    self.assertEqual([r['request_ids'] for r in rows if r['syscall']=='pwrite64'],[[1],[1],[]])
                else:
                    self.assertEqual([r['request_ids'] for r in rows],[[]] if cancelled else [[1],[],[2]] if two_dispatchers else [[1],[]])
                graph=[json.loads(x) for x in (run/'provenance.jsonl').read_text().splitlines()]
                self.assertEqual(sum(x.get('kind')=='ipc_sent' for x in graph),2 if two_dispatchers or relay else 1)
                if descendants:
                    edges=[x for x in graph if x.get('kind')=='spawned']
                    self.assertTrue(any(x['source'].endswith(':ipc:dispatcher-1/job-1') and x['target'].endswith(':process:300') for x in edges))
                    self.assertTrue(any(x['source'].endswith(':process:300') and x['target'].endswith(':process:400') for x in edges))
                if relay:
                    self.assertTrue(any(x.get('kind')=='ipc_sent' and x['source'].endswith(':ipc:dispatcher-1/job-1') and x['target'].endswith(':ipc:relay/1') for x in graph))
                if cancelled:
                    self.assertEqual(report['ipc_cancelled'],1)
                    self.assertTrue(any(x.get('kind')=='cancelled_before_execution' for x in graph))
                    return
                self.assertTrue(any(x.get('kind')=='executed' and ':ipc:dispatcher-1/job-1' in x['source'] for x in graph))

    def test_relay_retains_parent_job(self):self.check(relay=True)

    def test_descendants_preserve_ipc_and_process_chain(self):self.check(descendants=True)

    def test_cancelled_job_has_no_execution(self):self.check(cancelled=True)

    def test_valid_handoff_and_reset(self):self.check()

    def test_multiple_dispatcher_job_namespaces(self):self.check(two_dispatchers=True)

    def test_invalid_handoffs_fail_closed(self):
        for mutation in ['failed_marker_write','short_marker_write','cancel_then_execute','cancel_after_start','wrong_sender','unobserved_sender','missing_send','duplicate_send','wrong_context','zero_context','duplicate_enter','missing_leave','wrong_thread','duplicate_leave','context_switch']:
            with self.subTest(mutation=mutation):self.check(mutation)
