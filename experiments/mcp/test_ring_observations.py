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
