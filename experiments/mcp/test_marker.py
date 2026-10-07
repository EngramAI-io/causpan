import json
from pathlib import Path
import tempfile
import unittest
from attribute import marker, load_request_mapping


class MarkerSchemaTests(unittest.TestCase):
    def event(self,payload):
        return dict(syscall='write',paths=['/capture/native-events.jsonl'],tid=100,
                    args=f'9</capture/native-events.jsonl>, {json.dumps(payload)}, {len(payload.encode())}',
                    return_value=len(payload.encode()),source='strace.100:1')

    def test_schema_rejects_coercible_and_unknown_identities(self):
        valid=dict(csp=1,tid=100,request=1,operation=0,pointer=0,status=0,kind='JS_CONTEXT')
        self.assertEqual(marker(self.event(json.dumps(valid)),Path('/capture')),valid)
        for key,value in [('request',True),('request',1.0),('request','1'),('request',-1),
                          ('operation',2**64),('kind','FUTURE_CONTEXT'),('tid',False),('csp',True)]:
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                marker(self.event(json.dumps({**valid,key:value})),Path('/capture'))
        for payload in ['[]','null',json.dumps(valid)[:-1]+',"request":2}']:
            with self.subTest(payload=payload),self.assertRaises(ValueError):
                marker(self.event(payload),Path('/capture'))


class MappingSchemaTests(unittest.TestCase):
    def test_parent_identity_is_not_coerced(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'request-map.jsonl'
            root=dict(context=1,rpc_id='one',tool='test')
            for parents in [[True],[1.0],['1'],[2],[1,1],[],None]:
                with self.subTest(parents=parents):
                    path.write_text(json.dumps(root)+'\n'+json.dumps(dict(kind='join',context=2,parents=parents))+'\n')
                    with self.assertRaises(ValueError):load_request_mapping(path)
            path.write_text(json.dumps(root)+'\n'+json.dumps(dict(kind='join',context=2,parents=[1]))+'\n')
            self.assertEqual(len(load_request_mapping(path)),2)
            path.write_text('{"context":1,"context":2}\n')
            with self.assertRaises(ValueError):load_request_mapping(path)
