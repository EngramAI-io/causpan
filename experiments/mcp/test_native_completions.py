import struct
import tempfile
from pathlib import Path
import unittest
from inspect_native_completions import inspect


class NativeCompletionTests(unittest.TestCase):
    def log(self):
        sq=bytearray(128)
        for offset,identity in [(0,10),(64,11)]:
            sq[offset]=29;struct.pack_into('<i',sq,offset+4,7);struct.pack_into('<Q',sq,offset+32,identity)
        cq=struct.pack('<QiIQiI',11,0,0,10,0,0)
        def dump(data):
            return '\n'.join(f'0x{4096+i:x}:\t'+'\t'.join(f'0x{x:02x}' for x in data[i:i+8]) for i in range(0,len(data),8))
        return '\n'.join(['RING_ENTER fd=3 submit=2 wait=2 flags=1','SQ_COUNTERS head=0 tail=2 mask=255',dump(sq),
                          'SQ_ARRAY index0=0 index1=1','ENTER_RETURN result=2','CQ_RING fd=3 mask=511',
                          'CQ_COUNTERS head=0 tail=2',dump(cq),'[Inferior 1 exited normally]'])

    def test_out_of_order_identity_join_and_missing_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'log';text=self.log();path.write_text(text)
            self.assertEqual([o['user_data'] for o in inspect(path)['operations']],[11,10])
            for old,new in [('CQ_RING fd=3 mask=511\n',''),('ENTER_RETURN result=2','ENTER_RETURN result=1'),
                            ('SQ_ARRAY index0=0 index1=1','SQ_ARRAY index0=1 index1=0'),
                            ('0x0b','0x0a'),('exited normally','exited with code 1')]:
                path.write_text(text.replace(old,new))
                with self.subTest(old=old):
                    with self.assertRaises(ValueError):inspect(path)
