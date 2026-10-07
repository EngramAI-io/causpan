import unittest
import json
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path
from query import select_row, evidence_chain


class QueryTests(unittest.TestCase):
    def test_request_query_includes_ambiguous_candidate_without_claiming_ownership(self):
        row={'source':'strace.10:20','request_ids':[],'request_id':None,
             'candidate_request_ids':[3,'other'],'attribution':'ambiguous_resource',
             'paths':['TCP:[127.0.0.1:1->127.0.0.1:2]']}
        self.assertTrue(select_row(row,request=3))
        self.assertFalse(select_row(row,request=4))
        self.assertTrue(select_row(row,event='strace.10:20'))

    def test_ipc_query_reaches_request_through_job(self):
        graph=[
            dict(type='node',id='session:request:1',kind='mcp_request'),
            dict(type='node',id='session:ipc:job',kind='ipc_job'),
            dict(type='node',id='session:syscall:strace.200:5',kind='syscall'),
            dict(type='node',id='session:request:2',kind='mcp_request'),
            dict(type='edge',source='session:request:1',target='session:ipc:job',kind='ipc_sent',evidence='strace.100:3'),
            dict(type='edge',source='session:ipc:job',target='session:syscall:strace.200:5',kind='executed',evidence='strace.200:4'),
        ]
        result=evidence_chain(graph,[dict(source='strace.200:5')])
        self.assertEqual({r['id'] for r in result if r['type']=='node'},
                         {'session:request:1','session:ipc:job','session:syscall:strace.200:5'})
        self.assertEqual({r['kind'] for r in result if r['type']=='edge'},{'ipc_sent','executed'})

    def test_cancelled_request_without_syscalls_keeps_outcome(self):
        graph=[dict(type='node',id='request:1',kind='mcp_request',rpc_id=1),
               dict(type='node',id='request:2',kind='mcp_request',rpc_id=2),
               dict(type='node',id='ipc:1',kind='ipc_job'),
               dict(type='node',id='cancel:1',kind='ipc_cancellation'),
               dict(type='edge',source='request:1',target='ipc:1',kind='ipc_sent'),
               dict(type='edge',source='ipc:1',target='cancel:1',kind='cancelled_before_execution')]
        result=evidence_chain(graph,[],request=1)
        self.assertEqual({r['id'] for r in result if r['type']=='node'}, {'request:1','ipc:1','cancel:1'})
        self.assertEqual(evidence_chain(graph,[]),[])
        self.assertEqual(evidence_chain(graph,[],request=99),[])

    def test_failed_workload_option_keeps_integrity_and_oracle_gates(self):
        with tempfile.TemporaryDirectory() as directory:
            run=Path(directory)
            (run/'manifest.json').write_text(json.dumps({'status':'failed','error':'tool failed'}))
            hashes={}
            for name in ['causal-attribution.jsonl','provenance.jsonl']:
                (run/name).write_text('')
                hashes[name]=hashlib.sha256(b'').hexdigest()
            report={'valid':True,'errors':[],'output_sha256':hashes}
            (run/'causal-report.json').write_text(json.dumps(report))
            command=[sys.executable,str(Path(__file__).with_name('query.py')),str(run),'--request','1']
            self.assertNotEqual(subprocess.run(command,capture_output=True).returncode,0)
            command.append('--allow-failed-workload')
            result=subprocess.run(command,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads(result.stdout)['workload_status'],'failed')
            (run/'provenance.jsonl').write_text('corruption')
            self.assertNotEqual(subprocess.run(command,capture_output=True).returncode,0)
            (run/'provenance.jsonl').write_text('')
            (run/'control-score.json').write_text(json.dumps({'valid':False}))
            self.assertNotEqual(subprocess.run(command,capture_output=True).returncode,0)
            (run/'control-score.json').unlink()
            report['valid']=False;report['errors']=['unfinished IPC jobs']
            (run/'causal-report.json').write_text(json.dumps(report))
            self.assertNotEqual(subprocess.run(command,capture_output=True).returncode,0)
            report['valid']=True;report.pop('output_sha256')
            (run/'causal-report.json').write_text(json.dumps(report))
            self.assertNotEqual(subprocess.run(command,capture_output=True).returncode,0)


if __name__=='__main__':unittest.main()
