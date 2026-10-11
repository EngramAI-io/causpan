import unittest
from native_socket_lifetimes import link_lines


class NativeSocketLifetimeTests(unittest.TestCase):
    def test_reuse_and_failed_close_do_not_keep_old_installation(self):
        lines=['SOCKET_STOP thread=1 syscall=198 value=2','SOCKET_STOP thread=1 syscall=198 value=7',
               'SQE target=7 control=1','CLOSE_STOP thread=1 value=7','CLOSE_STOP thread=1 value=-4',
               'SQE target=7 control=1','SOCKET_STOP thread=1 syscall=198 value=2',
               'SOCKET_STOP thread=1 syscall=198 value=7','SQE target=7 control=1']
        result=link_lines('\n'.join(lines));refs=result['references']
        self.assertIsNone(refs[1]['installation'])
        self.assertNotEqual(refs[0]['installation'],refs[2]['installation'])
        self.assertEqual(result['linked'],2)
        with self.assertRaises(ValueError):link_lines('SOCKET_STOP thread=1 syscall=198 value=2')

    def test_installation_during_close_is_not_projected(self):
        text='\n'.join(['CLOSE_STOP thread=1 value=7',
                        'SOCKET_STOP thread=2 syscall=198 value=2',
                        'SOCKET_STOP thread=2 syscall=198 value=7',
                        'CLOSE_STOP thread=1 value=0','SQE target=7 control=1'])
        result=link_lines(text)
        self.assertEqual(result['linked'],0)
        self.assertEqual(result['installations'][0]['projection_rejected'],'overlapping_close')

    def test_close_completes_inside_installation_interval(self):
        text='\n'.join(['SOCKET_STOP thread=2 syscall=198 value=2',
                        'CLOSE_STOP thread=1 value=7','CLOSE_STOP thread=1 value=0',
                        'SOCKET_STOP thread=2 syscall=198 value=7','SQE target=7 control=1'])
        result=link_lines(text)
        self.assertEqual(result['linked'],0)
        self.assertEqual(result['installations'][0]['projection_rejected'],'overlapping_close')

    def test_control_descriptors_are_opt_in_and_close_invalidates(self):
        text='\n'.join(['CONTROL_FD_STOP thread=1 syscall=19 value=0',
                        'CONTROL_FD_STOP thread=1 syscall=19 value=9',
                        'SQE target=9 control=1','CLOSE_STOP thread=1 value=9',
                        'CLOSE_STOP thread=1 value=0','SQE target=9 control=1'])
        self.assertEqual(link_lines(text)['linked'],0)
        result=link_lines(text,include_controls=True)
        self.assertEqual(result['linked'],1)
        self.assertEqual(result['installations'][0]['kind'],'eventfd')
        self.assertIsNone(result['references'][1]['installation'])
