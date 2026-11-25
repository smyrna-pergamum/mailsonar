"""Optional local CLI adapters. Never executes log content or rule code."""
import argparse,json,sys
from pathlib import Path

def drain(events):
    from drain3 import TemplateMiner
    miner=TemplateMiner()
    out=[]
    for e in events:
        line=str(e.get('data',{}).get('raw') or e.get('action',''))[:65536]
        r=miner.add_log_message(line)
        out.append({'evidence':e['id'],'cluster_id':r['cluster_id'],'template':r['template_mined']})
    return out

def sigma(text):
    from sigma.collection import SigmaCollection
    rules=SigmaCollection.from_yaml(text)
    return [{'title':r.title,'id':str(r.id),'status':'parsed only; not evaluated'} for r in rules.rules]

def pdf(data,path):
    from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    from xml.sax.saxutils import escape
    s=getSampleStyleSheet(); flow=[Paragraph('MailSonar - Analyst report',s['Title'])]
    for title,value in [('Case',data.get('name','')),('Notes',data.get('notes','')),('Findings',data.get('findings',[])),('AI output (unverified)',data.get('ai_output_unverified',''))]:
        flow.append(Paragraph(title,s['Heading2']))
        raw=json.dumps(value,ensure_ascii=True) if not isinstance(value,str) else value
        for i in range(0,len(raw),500):
            flow.append(Paragraph(escape(raw[i:i+500]),s['BodyText']));flow.append(Spacer(1,4))
    SimpleDocTemplate(str(path)).build(flow)

def main():
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['drain','sigma','pdf']);p.add_argument('input');p.add_argument('--output');a=p.parse_args();path=Path(a.input)
    if path.stat().st_size>64*1024*1024: raise ValueError('Input too large')
    text=path.read_text(encoding='utf-8')
    if a.mode=='sigma': result=sigma(text)
    else:
        data=json.loads(text)
        if a.mode=='pdf':
            if not a.output: p.error('--output required')
            pdf(data,a.output);return
        result=drain(data if isinstance(data,list) else [e for f in data['evidence'] for e in f['events']])
    print(json.dumps(result,ensure_ascii=False))
if __name__=='__main__':main()
