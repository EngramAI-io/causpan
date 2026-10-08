"""Exercise the worker as a process so startup and embedded-child errors surface."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class WorkerProcessTests(unittest.TestCase):
    def test_worker_and_descendants_produce_effects_and_balanced_markers(self):
        for scenario in ('worker-context', 'worker-spawn', 'worker-grandchild', 'worker-relay', 'worker-rights'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                slots = root / 'slots.bin'
                slots.write_bytes(bytes(512))
                result = subprocess.run(
                    [sys.executable, str(Path(__file__).with_name('persistent_worker.py')), str(slots)],
                    input=json.dumps(dict(context='7', slot=2, job='test/1')) + '\n',
                    text=True, capture_output=True, timeout=15,
                    env={**os.environ, 'CAUSPAN_RUN': str(root), 'CAUSPAN_SCENARIO': scenario,
                         'CAUSPAN_WORKER_LEAF': ''})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), dict(slot=2, job='test/1'))
                self.assertEqual(slots.read_bytes()[256:264], b'worker:2')
                markers = [json.loads(line) for line in (root/'native-events.jsonl').read_text().splitlines()]
                entered = [r['job'] for r in markers if r['kind'] == 'IPC_ENTER']
                left = [r['job'] for r in markers if r['kind'] == 'IPC_LEAVE']
                self.assertEqual(sorted(entered), sorted(left))
                self.assertEqual(len(entered), 2 if scenario in {'worker-relay', 'worker-rights'} else 1)
                self.assertTrue(all(r['request'] == 7 for r in markers if r['kind'].startswith('IPC_')))
