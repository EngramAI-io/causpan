import unittest
from ring_coverage import ring_coverage


class RingCoverageTests(unittest.TestCase):
    def test_operation_and_enter_counts_have_distinct_denominators(self):
        events=[dict(syscall='io_uring_enter',source='batch',args='3, 3, 3, IORING_ENTER_GETEVENTS, NULL, 0',return_value=3),dict(syscall='io_uring_enter',source='unknown',args='4, 2, 2, IORING_ENTER_GETEVENTS, NULL, 0',return_value=2)]
        graph=[dict(type='node',kind='ring_operation',evidence='parent_snapshot_of_inherited_shared_ring',syscall_evidence='batch') for _ in range(3)]
        report=ring_coverage(events,graph)
        self.assertEqual(report['enters_with_attributed_operations'],1)
        self.assertEqual(report['enters_without_attributed_operations'],1)
        self.assertEqual(report['attributed_operations_by_evidence']['parent_snapshot_of_inherited_shared_ring'],3)
        self.assertFalse(report['submissions_decoded'])
        self.assertEqual(report['observed_uncovered_accepted_submissions'],2)
        graph[0]['syscall_evidence']='absent'
        with self.assertRaises(ValueError):ring_coverage(events,graph)
