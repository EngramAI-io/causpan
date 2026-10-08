import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from score_rights import score


class RightsOracleTests(unittest.TestCase):
    def test_received_fd_effects_and_negative_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            target = str(run/'sandbox/slots.bin')
            payload = json.dumps(json.dumps(dict(slot=1, context='1', job='j')))
            rows = []
            for direction, pid, fd in [('send',1,4), ('receive',2,9)]:
                rows.append(dict(source=direction, pid=pid, syscall='sendmsg' if direction=='send' else 'recvmsg',
                                 args=f'3, {{msg_iov=[{{iov_base={payload}}}]}}', paths=[], timestamp_ns=1,
                                 completion_ns=5, request_ids=[7] if direction=='send' else [],
                                 descriptor_rights=dict(decoded=True, succeeded=True, control_truncated=False,
                                                        direction=direction, fds=[fd])))
            for syscall, ts in [('pwrite64',6), ('pread64',7)]:
                rows.append(dict(source=syscall, pid=2, syscall=syscall, args=f'9<{target}>, "x", 1, 128',
                                 paths=[target], timestamp_ns=ts, request_ids=[7]))
            (run/'tool-calls.jsonl').write_text(json.dumps(dict(id=7, tool='worker_slot', arguments={'slot':1}))+'\n')
            def evaluate(data):
                (run/'causal-attribution.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in data))
                with contextlib.redirect_stdout(io.StringIO()):
                    return score(run)
            self.assertTrue(evaluate(rows)['valid'])
            bad_fd = copy.deepcopy(rows); bad_fd[2]['args'] = bad_fd[2]['args'].replace('9<','8<')
            wrong_owner = copy.deepcopy(rows); wrong_owner[2]['request_ids'] = [8]
            early_effect = copy.deepcopy(rows); early_effect[2]['timestamp_ns'] = 4
            opened = rows + [dict(source='open', pid=2, syscall='openat', paths=[target])]
            for bad in [rows[1:], bad_fd, wrong_owner, early_effect, opened]:
                with self.assertRaises(RuntimeError):
                    evaluate(bad)

            pair = dict(type='node', kind='descriptor_transfer', send='send', receive='receive', sender_fd=4, receiver_fd=9)
            (run/'provenance.jsonl').write_text(json.dumps(pair)+'\n')
            self.assertTrue(evaluate(rows)['valid'])
            pair['receiver_fd'] = 10
            (run/'provenance.jsonl').write_text(json.dumps(pair)+'\n')
            with self.assertRaises(RuntimeError):
                evaluate(rows)
