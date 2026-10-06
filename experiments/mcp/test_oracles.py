import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from score_control import score
from analyze import analyze

class OracleRegressionTests(unittest.TestCase):
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
