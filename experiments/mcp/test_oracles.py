import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from score_control import score
from analyze import analyze
from score_network import score as score_network

class OracleRegressionTests(unittest.TestCase):
    def test_network_candidate_coverage_reports_extras_instead_of_claiming_precision(self):
        with tempfile.TemporaryDirectory() as d:
            run=Path(d)
            (run/'run-config.json').write_text(json.dumps({'scenario':'network-shared'}))
            (run/'tool-calls.jsonl').write_text(''.join(json.dumps({'id':i+3,'tool':'tcp_roundtrip','arguments':{'slot':i}})+'\n' for i in range(2)))
            row=dict(source='line1',syscall='read',args='8<TCP:[127.0.0.1:1->127.0.0.1:2]>, "causpan-net:0\\ncauspan-net:1\\n", 64',
                     return_value=28,request_ids=[],candidate_request_ids=[3,4,5],paths=[],origin='async_context')
            writes=[dict(source=f'write{i}',syscall='write',args=f'8<TCP:[127.0.0.1:1->127.0.0.1:2]>, "causpan-net:{i}\\n", 14',
                         return_value=14,request_ids=[i+3],candidate_request_ids=[],paths=[],origin='async_context') for i in range(2)]
            (run/'causal-attribution.jsonl').write_text(''.join(json.dumps(item)+'\n' for item in [*writes,row]))
            result=score_network(run)
            self.assertTrue(result['valid'])
            self.assertEqual(result['mode'],'candidate_coverage')
            self.assertEqual(result['counts']['exact_events'],2)
            self.assertEqual(result['counts']['extra_candidate_edges'],1)

    def test_inbound_network_oracle_checks_accepted_socket_reads_and_writes(self):
        with tempfile.TemporaryDirectory() as d:
            run=Path(d)
            (run/'run-config.json').write_text(json.dumps({'scenario':'network-inbound'}))
            (run/'tool-calls.jsonl').write_text(json.dumps({'id':7,'tool':'tcp_accept','arguments':{'slot':3}})+'\n')
            rows=[dict(source='read',syscall='read',args='11<TCP:[local]>, "causpan-in:3\\n", 64',
                       return_value=13,request_ids=[7],candidate_request_ids=[],paths=[],origin='socket_lifecycle'),
                  dict(source='write',syscall='write',args='11<TCP:[local]>, "causpan-in:3\\n", 13',
                       return_value=13,request_ids=[7],candidate_request_ids=[],paths=[],origin='async_context')]
            (run/'causal-attribution.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in rows))
            result=score_network(run)
            self.assertTrue(result['valid'])
            self.assertEqual(result['counts']['read_events'],1)
            self.assertEqual(result['counts']['write_events'],1)
            self.assertEqual(result['counts']['exact_events'],2)

    def test_inbound_shared_stream_read_requires_all_request_candidates(self):
        with tempfile.TemporaryDirectory() as d:
            run=Path(d)
            (run/'run-config.json').write_text(json.dumps({'scenario':'network-inbound-shared'}))
            calls=[{'id':7+i,'tool':'tcp_accept','arguments':{'slot':i}} for i in range(2)]
            (run/'tool-calls.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in calls))
            rows=[dict(source='read',syscall='read',args='11<TCP:[local]>, "causpan-in:0\\ncauspan-in:1\\n", 64',
                       return_value=26,request_ids=[],candidate_request_ids=[7,8],paths=[],origin='socket_lifecycle'),
                  *[dict(source=f'write{i}',syscall='write',args=f'11<TCP:[local]>, "causpan-in:{i}\\n", 13',
                         return_value=13,request_ids=[7+i],candidate_request_ids=[],paths=[],origin='async_context') for i in range(2)]]
            (run/'causal-attribution.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in rows))
            result=score_network(run)
            self.assertTrue(result['valid'])
            self.assertEqual(result['mode'],'candidate_coverage')
            self.assertEqual(result['counts']['extra_candidate_edges'],0)
            self.assertEqual(result['counts']['covered_events'],3)

    def test_multi_parent_background_leak_is_not_hidden_by_null_scalar_id(self):
        with tempfile.TemporaryDirectory() as d:
            run=Path(d)
            (run/'tool-calls.jsonl').write_text(json.dumps({'id':1,'tool':'slot_io','end_ns':10,'arguments':{'slot':0,'rounds':1}})+'\n')
            rows=[]
            for offset,parents,syscall in [(0,[1],'pwrite64'),(0,[1],'pread64'),(12800000,[1,2],'pwrite64')]:
                rows.append(dict(source=f'line{len(rows)}',syscall=syscall,paths=[str(run/'sandbox/slots.bin')],
                                 args=f'3<{run}/sandbox/slots.bin>, "data", 4, {offset}',timestamp_ns=5,
                                 request_ids=parents,request_id=parents[0] if len(parents)==1 else None,
                                 attribution='bound' if len(parents)==1 else 'multi_parent',return_value=4))
            (run/'causal-attribution.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows))
            (run/'protocol.jsonl').write_text('')
            with contextlib.redirect_stdout(io.StringIO()),self.assertRaises(RuntimeError):score(run)
            report=json.loads((run/'control-score.json').read_text())
            self.assertEqual(report['counts']['wrong'],1)
    def test_duplicate_mcp_id_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            run=Path(d)
            row={'wall_ns':1,'direction':'request','message':{'id':1,'method':'tools/call','params':{'name':'read_text_file','arguments':{}}}}
            (run/'protocol.jsonl').write_text((json.dumps(row)+'\n')*2)
            with self.assertRaisesRegex(ValueError,'reused MCP'):analyze(run)

if __name__=='__main__':unittest.main()
