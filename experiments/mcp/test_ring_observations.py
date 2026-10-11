import copy
import unittest
from ring_observations import join_observations


class RingObservationTests(unittest.TestCase):
    def rows(self):
        return [dict(kind='sqe', user_data=i, opcode=23 if i<3 else 22,
                     fd=4 if i<3 else -1, offset=(i-1)*128, length=7, flags=0) for i in [1,2,3]] + [
            dict(kind='cqe', user_data=i, result=-9 if i==3 else 7, flags=0) for i in [3,1,2]]

    def test_identity_not_completion_order(self):
        result=join_observations(self.rows())
        self.assertEqual([r['user_data'] for r in result],[3,1,2])
        self.assertEqual([r['offset'] for r in result],[256,0,128])
        self.assertEqual([r['succeeded'] for r in result],[False,True,True])

    def test_unsupported_incomplete_or_aliased_observations_fail_closed(self):
        mutations=[lambda rows:rows.pop(),
                   lambda rows:rows.insert(1,copy.deepcopy(rows[0])),
                   lambda rows:rows.append(copy.deepcopy(rows[-1])),
                   lambda rows:rows[0].update(user_data=True),
                   lambda rows:rows[0].update(opcode=0),
                   lambda rows:rows[0].update(flags=1),
                   lambda rows:rows[-1].update(result=8),
                   lambda rows:rows[-1].update(flags=2),
                   lambda rows:rows[-1].update(user_data=99)]
        for mutate in mutations:
            rows=self.rows();mutate(rows)
            with self.assertRaises(ValueError):
                join_observations(rows)

class RingResourceTests(unittest.TestCase):
    def test_missing_mutation_result_does_not_preserve_stale_resource(self):
        from ring_observations import observed_file_resource
        opened=dict(pid=10,syscall='openat',args='AT_FDCWD, "/fixture/a", O_RDWR',
                    return_value=4,timestamp_ns=1,completion_ns=2,source='open',paths=['/fixture/a'])
        for syscall,args in [('dup2','5, 4'),('close_range','3, 8, 0'),
                             ('recvmsg','5, {}, 0'),('openat','AT_FDCWD, "/fixture/b", O_RDWR')]:
            mutation=dict(pid=10,syscall=syscall,args=args,return_value=None,
                          timestamp_ns=3,completion_ns=None,source='unknown',paths=[])
            with self.subTest(syscall=syscall):
                self.assertEqual(observed_file_resource([opened,mutation],10,4,10)['paths'],[])

    def test_path_projection_expires_on_close_and_descriptor_replacement(self):
        from ring_observations import observed_file_resource
        events=[dict(pid=10,syscall='openat',args='AT_FDCWD, "/fixture/a", O_RDWR',return_value=4,
                     timestamp_ns=1,completion_ns=2,source='open',paths=['/fixture/a'])]
        result=observed_file_resource(events,10,4,10)
        self.assertEqual(result['paths'],['/fixture/a'])
        self.assertEqual(result['resource_evidence'],'open')
        for syscall,args,result in [('close','4</fixture/a>',0),('dup2','5</fixture/b>, 4',4),
                                    ('close_range','3, 8, 0',0),('recvmsg','5<UNIX:[1->2]>, {}, 0',1)]:
            changed=events+[dict(pid=10,syscall=syscall,args=args,return_value=result,
                                timestamp_ns=3,completion_ns=4,source='replacement',paths=[])]
            self.assertEqual(observed_file_resource(changed,10,4,10)['paths'],[])
        self.assertEqual(observed_file_resource(events,10,-1,10)['resource_status'],'invalid_descriptor')
        self.assertEqual(observed_file_resource(events,10,4,1)['paths'],[])
        reused=events+[dict(pid=10,syscall='openat',args='AT_FDCWD, "/fixture/b", O_RDWR',return_value=4,
                           timestamp_ns=5,completion_ns=6,source='reopen',paths=['/fixture/b'])]
        self.assertEqual(observed_file_resource(reused,10,4,10)['paths'],['/fixture/b'])

class RingSubmissionBoundaryTests(unittest.TestCase):
    def test_waiting_batch_rejects_partial_submit_and_wait(self):
        from ring_observations import validate_waiting_enter
        valid=dict(args='3<anon_inode:[io_uring]>, 3, 3, IORING_ENTER_GETEVENTS, NULL, 0',return_value=3)
        self.assertEqual(validate_waiting_enter(valid,3),3)
        for args in ['3, 3, 0, 0, NULL, 0','3, 2, 3, IORING_ENTER_GETEVENTS, NULL, 0',
                     '3, 3, 1, IORING_ENTER_GETEVENTS, NULL, 0']:
            with self.assertRaises(ValueError):validate_waiting_enter(dict(args=args,return_value=3),3)
        with self.assertRaises(ValueError):validate_waiting_enter(dict(args=valid['args'],return_value=2),3)

    def test_descriptor_reused_after_preparation_resolves_at_submission(self):
        from ring_observations import observed_file_resource
        events=[dict(pid=10,syscall='openat',args='AT_FDCWD, "/fixture/a", O_RDWR',return_value=4,
                     timestamp_ns=1,completion_ns=2,source='open-a',paths=['/fixture/a']),
                dict(pid=10,syscall='close',args='4</fixture/a>',return_value=0,
                     timestamp_ns=6,completion_ns=7,source='close-a',paths=['/fixture/a']),
                dict(pid=10,syscall='openat',args='AT_FDCWD, "/fixture/b", O_RDWR',return_value=4,
                     timestamp_ns=8,completion_ns=9,source='open-b',paths=['/fixture/b'])]
        self.assertEqual(observed_file_resource(events,10,4,5)['paths'],['/fixture/a'])
        self.assertEqual(observed_file_resource(events,10,4,10)['paths'],['/fixture/b'])

class RingScopeTests(unittest.TestCase):
    def test_setup_flags_and_execution_scope_are_explicit(self):
        from ring_observations import validate_scoped_ring
        setup=dict(args='8, {flags=0, sq_off={flags=36}}')
        validate_scoped_ring(setup,[])
        for args in ['8, {}','8, {flags=IORING_SETUP_SQPOLL}',
                     '8, {flags=0x2, sq_off={flags=0}}']:
            with self.assertRaises(ValueError):validate_scoped_ring(dict(args=args),[])
        for syscall in ['clone','clone3','fork','vfork','io_uring_register']:
            for result in [0,42,None]:
                with self.subTest(syscall=syscall,result=result):
                    with self.assertRaises(ValueError):
                        validate_scoped_ring(setup,[dict(syscall=syscall,return_value=result)])
            validate_scoped_ring(setup,[dict(syscall=syscall,return_value=-1)])
