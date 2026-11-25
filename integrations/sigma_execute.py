"""Optional pySigma SQLite backend. Runs only single-event detections on a disposable database."""
import argparse,json,sqlite3,time
from pathlib import Path
FIELDS=('id','source','timestamp','sender','recipient','ip','message_id','action','vendor','queue_id','raw')

def readonly_queries(events,queries):
    if len(events)>20000 or len(queries)>100: raise ValueError('Query/record limit exceeded')
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE logs ('+','.join(f'"{k}" TEXT COLLATE NOCASE' for k in FIELDS)+')')
        db.executemany('INSERT INTO logs VALUES ('+','.join('?' for _ in FIELDS)+')', [tuple(str(e.get('data',{}).get('raw','')) if k=='raw' else (str(e[k]) if e.get(k) not in (None,'') else None) for k in FIELDS) for e in events])
        db.commit(); db.execute('PRAGMA query_only=ON')
        allowed_functions={'like','glob','lower','upper','coalesce','ifnull','length','substr','replace','trim','ltrim','rtrim','cast','strftime','typeof','abs','round'}
        def authorize(action,a,b,db_name,source):
            if action==sqlite3.SQLITE_SELECT or (action==sqlite3.SQLITE_READ and a=='logs' and db_name=='main') or (action==sqlite3.SQLITE_FUNCTION and (b or '').lower() in allowed_functions):return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY
        db.set_authorizer(authorize)
        deadline=time.monotonic()+15
        db.set_progress_handler(lambda:int(time.monotonic()>deadline),1000)
        results=[]
        for q in queries:
            if not isinstance(q,str) or len(q)>200000 or not q.lstrip().upper().startswith('SELECT '):raise ValueError('Only bounded SELECT detections supported')
            c=db.execute(q)
            columns=[d[0] for d in c.description]
            if 'id' not in columns:raise ValueError('Detection must return evidence ID')
            idx=columns.index('id'); ids=list(dict.fromkeys(r[idx] for r in c.fetchmany(20001) if r[idx]))
            results.append(ids)
        return results

def run(events,yaml):
    from sigma.collection import SigmaCollection
    from sigma.backends.sqlite import sqliteBackend
    if len(yaml)>128*1024:raise ValueError('Rule too large')
    rules=SigmaCollection.from_yaml(yaml)
    if len(rules.rules)!=1 or type(rules.rules[0]).__name__!='SigmaRule':raise ValueError('One single-event Sigma rule required; correlations not supported')
    rule=rules.rules[0]
    queries=sqliteBackend(fulltext_field='raw').convert(rules)
    result=readonly_queries(events,queries)
    return {'rule':str(rule.id or rule.title),'title':str(rule.title),'matches':list(dict.fromkeys(i for ids in result for i in ids)), 'warning':'Only normalized Mail DFIR fields; verify logsource and mappings. Unsupported functions and correlations fail closed.'}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('case');p.add_argument('rule');a=p.parse_args()
    c,r=Path(a.case),Path(a.rule)
    if c.stat().st_size>64*1024*1024 or r.stat().st_size>128*1024:raise ValueError('Input limit exceeded')
    case=json.loads(c.read_text(encoding='utf-8'));events=[e for f in case['evidence'] for e in f['events']]
    print(json.dumps(run(events,r.read_text(encoding='utf-8')),ensure_ascii=False))
