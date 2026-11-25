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
    def test_cli_uses_canonical_writer(self):
        proc=subprocess.run([sys.executable,'-I',str(ROOT/'integrations/pdf_report.py')],input=b'{"locale":"de"}',capture_output=True,check=True,timeout=20)
        self.assertTrue(proc.stdout.startswith(b'%PDF-'))

    @unittest.skipUnless(importlib.util.find_spec('pypdf'),'pypdf required for Unicode verification')
    def test_unicode_languages_and_markup(self):
        import io
        from pypdf import PdfReader
        for locale,title in [('tr','İnceleme raporu'),('de','Untersuchungsbericht'),('en','Investigation report')]:
            data={'locale':locale,'name':'Şüpheli ileti - Größe','notes':'<img src="file:///private"/>','findings':[]}
            proc=subprocess.run([sys.executable,'-I',str(ROOT/'src-tauri/src/pdf_report.py')],input=json.dumps(data).encode(),capture_output=True,check=True,timeout=20)
            text='\n'.join(page.extract_text() for page in PdfReader(io.BytesIO(proc.stdout)).pages)
            self.assertIn(title,text);self.assertIn('Şüpheli ileti - Größe',text);self.assertIn('<img',text)
if __name__=='__main__':unittest.main()
