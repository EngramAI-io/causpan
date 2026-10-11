import tempfile
from pathlib import Path
import unittest
from inspect_native_windows import inspect


class NativeWindowTests(unittest.TestCase):
    def batch(self,head,tail,index):
        return f'''BATCH fd=3 head={head} tail={tail} mask=255
SQE index={index} opcode=29 fd=7 user_data=42
RETURN result=1
COMPLETIONS fd=3 head={head} tail={tail} mask=511
CQE user_data=42 result=0 flags=0
BATCH_END
'''

    def test_wrapped_counters_and_completed_identity_reuse(self):
        text=self.batch(4294967295,0,255)+self.batch(0,1,0)+'exited normally\n'
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'log';path.write_text(text)
            self.assertEqual(inspect(path)['operations'],2)
            for old,new in [('RETURN result=1','RETURN result=0'),('CQE user_data=42','CQE user_data=43'),
                            ('mask=511','mask=255'),('BATCH_END\n','')]:
                path.write_text(text.replace(old,new,1))
                with self.subTest(old=old):
                    with self.assertRaises(ValueError):inspect(path)

    def test_missing_batch_and_shifted_completion_window_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'log'
            for text in [self.batch(0,1,0)+self.batch(2,3,2),
                         self.batch(0,1,0).replace('COMPLETIONS fd=3 head=0 tail=1','COMPLETIONS fd=3 head=1 tail=2')]:
                path.write_text(text+'exited normally\n')
                with self.assertRaises(ValueError):inspect(path)

    def test_epoll_target_fields_and_unsupported_control(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'log'
            text=self.batch(0,1,0).replace('opcode=29 fd=7 user_data=42','opcode=29 fd=7 user_data=42 target=12 control=1')+'exited normally\n'
            path.write_text(text);operation=inspect(path)['batches'][0]['operations'][0]
            self.assertEqual((operation['target_fd'],operation['control_operation']),(12,1))
            path.write_text(text.replace('control=1','control=99'))
            with self.assertRaises(ValueError):inspect(path)

    def test_record_phase_order_is_required(self):
        text=self.batch(0,1,0)+'exited normally\n'
        mutations=[text.replace('RETURN result=1','RETURN result=1\nRETURN result=1'),
                   text.replace('RETURN result=1\n',''),
                   text.replace('COMPLETIONS fd=3 head=0 tail=1 mask=511\n',''),
                   'BATCH_END\n'+text]
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'log'
            for changed in mutations:
                path.write_text(changed)
                with self.assertRaises(ValueError):inspect(path)

    def test_native_submission_flags_are_not_silently_erased(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'log'
            text=self.batch(0,1,0).replace('user_data=42\nRETURN','user_data=42 target=12 control=1 sqflags=0\nRETURN')+'exited normally\n'
            path.write_text(text)
            self.assertEqual(inspect(path)['batches'][0]['operations'][0]['sqe_flags'],0)
            path.write_text(text.replace('sqflags=0','sqflags=1'))
            with self.assertRaisesRegex(ValueError,'SQE flags'):inspect(path)

    def test_completion_modes_and_ranges_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'log';text=self.batch(0,1,0)+'exited normally\n'
            for old,new in [('flags=0','flags=2'),('result=0 flags','result=2147483648 flags'),
                            ('CQE user_data=42','CQE user_data=-1')]:
                path.write_text(text.replace(old,new))
                with self.assertRaises(ValueError):inspect(path)
