import unittest
from score_native_graph import evaluate, evaluate_shared_sequence

class GraphScoreTests(unittest.TestCase):
    def fixture(self):
        graph={'nodes':[{'id':'r1','kind':'request','rpc_id':1},{'id':'r2','kind':'request','rpc_id':2},
                        {'id':'op','kind':'ring_operation','target':7}],
               'edges':[{'source':'r2','target':'op'}]}
        oracle=[{'kind':'request','rpc_id':i,'token':str(i)} for i in [1,2]]
        oracle += [{'kind':'socket','token':str(i),'fd':7} for i in [1,2]]
        actions=[dict(token=str(i),action=a,fd=7,result=0,turn=0) for i in [1,2] for a in ['stop','start']]
        return graph,oracle,actions

    def test_shared_parent_swap_requires_sequence_oracle(self):
        graph,oracle,actions=self.fixture()
        self.assertEqual(evaluate_shared_sequence(evaluate(graph,oracle),oracle,actions)['mismatches'],0)
        graph['edges'][0]['source']='r1'
        score=evaluate(graph,oracle)
        self.assertEqual(score['mismatches'],0)
        self.assertEqual(evaluate_shared_sequence(score,oracle,actions)['mismatches'],2)

    def test_turn_boundary_or_missing_action_invalidates_oracle(self):
        graph,oracle,actions=self.fixture();score=evaluate(graph,oracle)
        actions[-1]['turn']=1
        with self.assertRaises(ValueError):evaluate_shared_sequence(score,oracle,actions)
        with self.assertRaises(ValueError):evaluate_shared_sequence(score,oracle,actions[:-1])
