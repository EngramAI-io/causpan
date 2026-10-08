import copy
import unittest
from descriptor_transfers import pair_transfers


class DescriptorTransferTests(unittest.TestCase):
    def fixture(self):
        creation=dict(source='pair', syscall='socketpair', return_value=0, timestamp_ns=0,
                      args='AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, [3<UNIX:[1->2]>, 4<UNIX:[2->1]>]')
        events=[creation]
        for n in range(2):
            for direction, pid, endpoint, start, end, fd in [('send',1,'1->2',10+n*20,11+n*20,7),('receive',2,'2->1',5+n*20,12+n*20,8+n)]:
                events.append(dict(source=f'{direction}{n}', syscall='sendmsg' if direction=='send' else 'recvmsg',
                    pid=pid, timestamp_ns=start, completion_ns=end, return_value=10,
                    args=f'3<UNIX:[{endpoint}]>, {{msg_flags=0}}, 0',
                    descriptor_rights=dict(fds=[fd], decoded=True, succeeded=True, control_truncated=False)))
        return events

    def test_blocking_receives_pair_by_observed_order_not_entry_interleaving(self):
        result=pair_transfers(self.fixture())
        self.assertEqual(len(result['pairs']),2)
        self.assertEqual(result['rejected_channels'],[])
        self.assertEqual([(p['send'],p['receive']) for p in result['pairs']], [('send0','receive0'),('send1','receive1')])

    def test_ambiguous_or_incomplete_channels_never_emit_partial_edges(self):
        mutations=[lambda e:e.pop(),
                   lambda e:e[1].update(completion_ns=31),
                   lambda e:e[2].update(completion_ns=None),
                   lambda e:e[2].update(return_value=9),
                   lambda e:e[2]['descriptor_rights'].update(control_truncated=True),
                   lambda e:e[2]['descriptor_rights'].update(fds=[8,9]),
                   lambda e:e[2].update(args=e[2]['args'].replace('msg_flags=0','msg_flags=MSG_PEEK')),
                   lambda e:e.append(copy.deepcopy(e[0]))]
        for mutate in mutations:
            events=self.fixture();mutate(events)
            result=pair_transfers(events)
            self.assertEqual(result['pairs'],[])
            self.assertTrue(result['rejected_channels'])

    def test_no_socketpair_or_stream_channel_is_not_inferred(self):
        events=self.fixture()[1:]
        self.assertEqual(pair_transfers(events)['pairs'],[])
        events=self.fixture();events[0]['args']=events[0]['args'].replace('SOCK_DGRAM','SOCK_STREAM')
        self.assertEqual(pair_transfers(events)['pairs'],[])

    def test_secondary_fd_channel_operation_is_not_ignored(self):
        events=self.fixture()
        events.append(dict(source='splice', syscall='splice', return_value=10, timestamp_ns=15,
                           args='9<pipe:[9]>, NULL, 3<UNIX:[1->2]>, NULL, 10, 0'))
        self.assertEqual(pair_transfers(events)['pairs'], [])

    def test_peerless_channel_observation_is_not_silently_omitted(self):
        events=self.fixture()
        events.append(dict(source='unresolved-recv', syscall='recvmsg', return_value=10, timestamp_ns=15,
                           completion_ns=16, args='3<UNIX:[2]>, {msg_flags=0}, 0'))
        self.assertEqual(pair_transfers(events)['pairs'], [])

    def test_unobserved_ring_operations_and_reused_inode_reject_pairing(self):
        events=self.fixture()
        events.append(dict(source='ring', syscall='io_uring_enter', return_value=1, timestamp_ns=20, args='9, 1, 0, 0, NULL, 0'))
        self.assertEqual(pair_transfers(events)['pairs'], [])
        events=self.fixture()
        other=copy.deepcopy(events[0]);other['source']='other-pair'
        other['args']=other['args'].replace('1->2','1->3').replace('2->1','3->1')
        events.append(other)
        self.assertEqual(pair_transfers(events)['pairs'], [])

    def test_payload_cannot_forge_secondary_endpoint_activity(self):
        events=self.fixture()
        events[1]['args']='3<UNIX:[1->2]>, {msg_iov=[{iov_base="4<UNIX:[2]> MSG_PEEK", iov_len=10}], msg_flags=0}, 0'
        self.assertEqual(len(pair_transfers(events)['pairs']),2)

    def test_failed_ring_creation_does_not_imply_ring_activity(self):
        events=self.fixture()
        events.append(dict(source='ring', syscall='io_uring_setup', return_value=-1, timestamp_ns=1, args='256, {flags=0}'))
        self.assertEqual(len(pair_transfers(events)['pairs']), 2)
