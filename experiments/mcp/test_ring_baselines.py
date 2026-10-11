import unittest
from ring_baselines import evaluate


class RingBaselineTests(unittest.TestCase):
    def test_window_reduces_candidates_without_inventing_single_owner(self):
        calls=[dict(id=i,arguments={'slot':i},start_ns=0 if i<2 else 20,end_ns=10 if i<2 else 30) for i in range(4)]
        events=[dict(source='first',timestamp_ns=5),dict(source='second',timestamp_ns=25)]
        operations=[dict(offset=i*512,syscall_evidence='first' if i<2 else 'second') for i in range(4)]
        result=evaluate(calls,operations,events)
        self.assertEqual(result['pid_lifetime']['candidate_count_histogram'],{4:4})
        self.assertEqual(result['request_window_at_enter']['candidate_count_histogram'],{2:4})
        for baseline in result.values():
            self.assertEqual(baseline['counts']['covered'],4)
            self.assertEqual(baseline['counts']['exact_correct'],0)
