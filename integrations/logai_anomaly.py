"""Optional LogAI isolation-forest adapter for historical vs later email event features."""
import argparse,json,math
from datetime import datetime
from pathlib import Path
from collections import Counter

def features(events):
    dated=[]
    for e in events:
        t=str(e.get('timestamp',''))
        try:
            d=datetime.fromisoformat(t.replace('Z','+00:00'))
            if d.tzinfo is None:continue
            dated.append((d.timestamp(),e))
        except (ValueError,OverflowError):continue
    dated.sort(key=lambda x:x[0]); split=int(len(dated)*.7)
    if split<30 or len(dated)-split<10:raise ValueError('At least 43 valid timestamped records needed; more history recommended')
    # Fit categorical frequencies on historical records only.
    fields=('action','sender','recipient','ip','vendor')
    counts={f:Counter(str(e.get(f,'')) for _,e in dated[:split]) for f in fields}
    def vector(e):return [math.log1p(counts[f].get(str(e.get(f,'')),0)) for f in fields]
    return [e['id'] for _,e in dated[split:]],[vector(e) for _,e in dated[:split]],[vector(e) for _,e in dated[split:]]

def analyze(events):
    import pandas as pd
    from logai.analysis.anomaly_detector import AnomalyDetector,AnomalyDetectionConfig
    from logai.algorithms.anomaly_detection_algo.isolation_forest import IsolationForestParams
    ids,train,test=features(events)
    model=AnomalyDetector(AnomalyDetectionConfig(algo_name='isolation_forest',algo_params=IsolationForestParams(n_estimators=100,max_features=5)))
    model.fit(pd.DataFrame(train));pred=model.predict(pd.DataFrame(test))
    vals=pred.to_numpy().reshape(-1).tolist()
    if len(vals)!=len(ids) or any(v not in (0,1) for v in vals):raise ValueError('Unexpected LogAI prediction format; refusing to infer labels')
    return {'findings':[{'rule':'LOGAI-001','severity':'medium','description':'LogAI isolation-forest outlier; verify baseline and source coverage','evidence':[i]} for i,v in zip(ids,vals) if v==1], 'evaluated':len(ids),'training':len(train)}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('case');a=p.parse_args();path=Path(a.case)
    if path.stat().st_size>64*1024*1024:raise ValueError('Input too large')
    case=json.loads(path.read_text(encoding='utf-8'));events=[e for f in case['evidence'] for e in f['events']]
    if len(events)>20000:raise ValueError('Too many events')
    print(json.dumps(analyze(events),ensure_ascii=False))
