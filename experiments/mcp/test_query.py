import unittest
from query import select_row


class QueryTests(unittest.TestCase):
    def test_request_query_includes_ambiguous_candidate_without_claiming_ownership(self):
        row={'source':'strace.10:20','request_ids':[],'request_id':None,
             'candidate_request_ids':[3,'other'],'attribution':'ambiguous_resource',
             'paths':['TCP:[127.0.0.1:1->127.0.0.1:2]']}
        self.assertTrue(select_row(row,request=3))
        self.assertFalse(select_row(row,request=4))
        self.assertTrue(select_row(row,event='strace.10:20'))


if __name__=='__main__':unittest.main()
