import json
from pathlib import Path
import tempfile
import unittest
from run import validate_agent


class AgentValidationTests(unittest.TestCase):
    def test_relay_validation_rejects_errors_duplicates_and_false_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'sandbox').mkdir()
            payload = bytearray(512)
            for n in range(4):
                payload[n*128:n*128+8] = f'worker:{n}'.encode()
            (root/'sandbox/slots.bin').write_bytes(payload)
            calls = [dict(type='item.completed', item=dict(type='mcp_tool_call', server='causpan_fs',
                     status='completed', tool='worker_slot', arguments={'slot':n})) for n in range(4)]
            calls += [dict(type='item.completed', item=dict(type='mcp_tool_call', server='causpan_fs',
                      status='completed', tool='barrier', arguments={})), dict(type='turn.completed')]
            def write(rows, error=False):
                (root/'agent.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows))
                (root/'protocol.jsonl').write_text(json.dumps(dict(direction='response', message={'result':{'isError':error}}))+'\n')
            write(calls)
            validate_agent(root, 'worker-relay')
            for rows, error in [(calls, True), (calls[:-1], False), ([calls[0], *calls[1:3], calls[0], *calls[4:]], False)]:
                write(rows, error)
                with self.assertRaises(RuntimeError):
                    validate_agent(root, 'worker-relay')
            write(calls)
            (root/'sandbox/slots.bin').write_bytes(bytes(512))
            with self.assertRaisesRegex(RuntimeError, 'output mismatch'):
                validate_agent(root, 'worker-relay')
