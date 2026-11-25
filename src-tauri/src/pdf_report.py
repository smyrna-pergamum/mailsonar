"""Local PDF report generator. Reads bounded JSON from stdin, writes PDF to stdout."""
import io, json, sys
from xml.sax.saxutils import escape
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

LIMIT = 2 * 1024 * 1024

def generate(data):
    if not isinstance(data, dict): raise ValueError('Report must be an object')
    styles = getSampleStyleSheet()
    flow = [Paragraph('MailSonar | Investigation report', styles['Title']),
            Paragraph('Analyst review required. Indicators and AI claims are not verified incidents.', styles['BodyText']), Spacer(1, 12)]
    def paragraph(value):
        value = str(value)
        # No untrusted ReportLab markup, links or external resource references.
        value = ''.join(c if c in '\n\t' or ord(c)>=32 else '?' for c in value)
        for start in range(0, len(value) or 1, 450):
            flow.append(Paragraph(escape(value[start:start+450]).replace('\n','<br/>'), styles['BodyText']))
            flow.append(Spacer(1,4))
    for label, value in [('Case',data.get('name','')),('Export timestamp',data.get('exported_at','')),('Analyst notes',data.get('notes',''))]:
        flow.append(Paragraph(label,styles['Heading2'])); paragraph(value)
    flow.append(Paragraph('Evidence manifest',styles['Heading2']))
    for f in data.get('evidence',[]):
        paragraph(f"{f.get('source','')} | {f.get('bytes','')} bytes | SHA-256: {f.get('sha256','')}")
    flow.append(Paragraph('Detection findings',styles['Heading2']))
    for finding in data.get('findings',[]):
        paragraph(f"{finding.get('severity','')} | {finding.get('rule','')} | {finding.get('description','')}")
        paragraph('Evidence IDs: '+', '.join(map(str,finding.get('evidence',[]))))
    flow.append(Paragraph('AI assessment (unverified)',styles['Heading2']))
    paragraph(data.get('ai_output_unverified',''))
    output=io.BytesIO()
    def footer(canvas,doc):
        canvas.saveState();canvas.setFont('Helvetica',9);canvas.drawString(42,30,'MailSonar | Analyst work product');canvas.drawRightString(A4[0]-42,30,str(doc.page));canvas.restoreState()
    SimpleDocTemplate(output,pagesize=A4,leftMargin=42,rightMargin=42,topMargin=45,bottomMargin=50,title='MailSonar Investigation Report').build(flow,onFirstPage=footer,onLaterPages=footer)
    return output.getvalue()

def main():
    raw=sys.stdin.buffer.read(LIMIT+1)
    if len(raw)>LIMIT: raise ValueError('Report exceeds 2 MiB limit')
    result=generate(json.loads(raw))
    if len(result)>8*1024*1024: raise ValueError('PDF exceeds 8 MiB limit')
    sys.stdout.buffer.write(result)
if __name__=='__main__': main()
