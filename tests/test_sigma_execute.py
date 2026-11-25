import sys,unittest,sqlite3
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'integrations'))
from sigma_execute import readonly_queries
class SigmaSQL(unittest.TestCase):
    def test_readonly_matching(self):
        self.assertEqual(readonly_queries([{'id':'e1','action':'Send'},{'id':'e2','action':'receive'}],["SELECT * FROM logs WHERE action='send'"]),[['e1']])
    def test_nonselect_rejected(self):
        with self.assertRaises(ValueError):readonly_queries([],['DROP TABLE logs'])
    def test_metadata_rejected(self):
        with self.assertRaises(sqlite3.DatabaseError):readonly_queries([],['SELECT * FROM sqlite_master'])
    def test_unapproved_function_rejected(self):
        with self.assertRaises(sqlite3.DatabaseError):readonly_queries([],['SELECT load_extension(\'x\') AS id FROM logs'])
if __name__=='__main__':unittest.main()
