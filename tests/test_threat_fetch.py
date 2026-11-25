import unittest,sys
from pathlib import Path
from urllib.parse import urlsplit,parse_qs
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'integrations'))
from threat_fetch import fetch
class Pagination(unittest.TestCase):
    def test_all_pages_same_origin(self):
        calls=[]
        def fake(url,mode,key):
            calls.append(url);self.assertEqual(urlsplit(url).hostname,'example.test');self.assertEqual(key,'key')
            return {'objects':[1],'more':True,'next':'https://other.test/?a=1'} if len(calls)==1 else {'objects':[2],'more':False}
        self.assertEqual(fetch('https://example.test/objects?limit=2','taxii','key',fake)['objects'],[1,2])
        self.assertEqual(parse_qs(urlsplit(calls[1]).query)['next'],['https://other.test/?a=1'])
    def test_loop_rejected(self):
        with self.assertRaises(ValueError): fetch('https://example.test/objects','taxii','',lambda *a:{'objects':[],'more':True,'next':'same'})
    def test_limit_rejected(self):
        with self.assertRaises(ValueError): fetch('https://example.test/objects','taxii','',lambda *a:{'objects':[1,2]},max_objects=1)
    def test_page_limit(self):
        with self.assertRaises(ValueError): fetch('https://example.test/objects','taxii','',lambda *a:{'objects':[],'more':True,'next':'new'},max_pages=1)
if __name__=='__main__':unittest.main()
