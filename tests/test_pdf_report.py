import importlib.util,subprocess,sys,unittest,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
@unittest.skipUnless(importlib.util.find_spec('reportlab'),'Optional ReportLab dependency unavailable')
class ReportTests(unittest.TestCase):
    def test_embedded_generator(self):
        script=ROOT/'src-tauri/src/pdf_report.py'
        data={'name':'Sample case <img src="file:///private"/>','evidence':[{'source':'test.log','sha256':'a'*64,'bytes':15}], 'findings':[{'rule':'R1','severity':'medium','description':'Review event','evidence':['id1']}], 'ai_output_unverified':'Unverified hypothesis'}
        proc=subprocess.run([sys.executable,'-I',str(script)],input=json.dumps(data).encode(),capture_output=True,check=True,timeout=20)
        self.assertTrue(proc.stdout.startswith(b'%PDF-'));self.assertTrue(proc.stdout.rstrip().endswith(b'%%EOF'))
    def test_source_sync(self):
        self.assertEqual((ROOT/'integrations/pdf_report.py').read_bytes(),(ROOT/'src-tauri/src/pdf_report.py').read_bytes())
if __name__=='__main__':unittest.main()
