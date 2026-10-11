import copy
import struct
import unittest
from ring_memory_probe import decode
from ring_observations import join_observations


class RingMemoryTests(unittest.TestCase):
    def fixture(self):
        meta=dict(sq_entries=2,cq_entries=2,sq_size=24,cq_size=48,
                  sq_head=0,sq_tail=4,sq_mask=8,sq_array=16,
                  cq_head=0,cq_tail=4,cq_mask=8,cqes=16)
        sq=bytearray(24);cq=bytearray(48);sqes=bytearray(128)
        # Counters wrap UINT32_MAX; logical SQ index is 1, array selects SQE 0.
        struct.pack_into('<III',sq,0,0xffffffff,0,1)
        struct.pack_into('<I',sq,20,0)
        struct.pack_into('<BBHiQQI',sqes,0,23,0,0,4,128,0,7)
        struct.pack_into('<Q',sqes,32,123)
        struct.pack_into('<III',cq,0,0xffffffff,0,1)
        struct.pack_into('<QiI',cq,32,123,7,0)
        return meta,sq,sqes,cq

    def test_counter_wrap_and_array_indirection(self):
        records=decode(*self.fixture())
        operations=join_observations(records)
        self.assertEqual(len(operations),1)
        self.assertEqual((operations[0]['user_data'],operations[0]['offset'],operations[0]['result']),(123,128,7))

    def test_invalid_layouts_and_truncation_rejected(self):
        for key,value in [('sq_head',-4),('sq_head',True),('sq_mask',4),
                          ('sq_array',0),('cqes',32),('cq_tail',100),('sq_entries',3)]:
            args=list(self.fixture());args[0]=copy.deepcopy(args[0]);args[0][key]=value
            with self.subTest(key=key,value=value):
                with self.assertRaises(ValueError):decode(*args)
        for index in [1,2,3]:
            args=list(self.fixture());args[index]=args[index][:-1]
            with self.assertRaises(ValueError):decode(*args)

    def test_auxiliary_semantics_cannot_disappear_during_decoding(self):
        for offset in [2,3,28,31,40,42,44,48,63]:
            args=list(self.fixture());args[2][offset]=1
            with self.subTest(offset=offset):
                with self.assertRaisesRegex(ValueError,'auxiliary SQE'):
                    decode(*args)
