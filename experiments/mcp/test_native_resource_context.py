import json
import unittest
from native_resource_context import join


def marker(request):
    return 'MARKER_WRITE '+json.dumps(dict(tid=101,marker=dict(kind='JS_CONTEXT',request=request)))


class NativeResourceContextTests(unittest.TestCase):
    def test_creation_survives_context_reset_but_not_descriptor_reuse(self):
        lines=['LIFECYCLE_THREAD thread=1 tid=101',marker(1),
               'SOCKET_STOP thread=1 syscall=198 value=2','SOCKET_STOP thread=1 syscall=198 value=7',
               marker(0),'SQE target=7 control=1','CLOSE_STOP thread=1 value=7',
               'CLOSE_STOP thread=1 value=0','SQE target=7 control=1',marker(2),
               'SOCKET_STOP thread=1 syscall=198 value=2','SOCKET_STOP thread=1 syscall=198 value=7',
               marker(0),'SQE target=7 control=1']
        result=join('\n'.join(lines))
        self.assertEqual([r['resource_creation_context'] for r in result['references']],[1,None,2])

    def test_thread_mapping_required_and_context_disagreement_abstains(self):
        lines=[marker(1),'SOCKET_STOP thread=1 syscall=198 value=2',marker(2),
               'SOCKET_STOP thread=1 syscall=198 value=7','SQE target=7 control=1']
        with self.assertRaises(ValueError):join('\n'.join(lines))
        result=join('\n'.join(['LIFECYCLE_THREAD thread=1 tid=101']+lines))
        self.assertIsNone(result['references'][0]['resource_creation_context'])
