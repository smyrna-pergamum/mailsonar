// Deterministic, offline analysis. No network calls.
export function correlate(events) {
 const groups=new Map(), findings=[];
 for(const e of events){
  for(const [kind,val] of [['message',e.message_id],['sender',e.sender],['ip',e.ip]]){
   if(!val||!val.trim())continue;const key=kind+':'+val.trim().toLowerCase();
   if(!groups.has(key))groups.set(key,{kind,value:val,events:[]});groups.get(key).events.push(e);
  }
 }
 for(const g of groups.values()){
  if(g.kind==='sender'||g.kind==='ip'){
   const failures=g.events.filter(e=>/authentication fail|failed login|invalid credentials|loginfailed/i.test(JSON.stringify(e.data))).map(e=>({e,t:Date.parse(e.timestamp)})).filter(x=>Number.isFinite(x.t)).sort((a,b)=>a.t-b.t);
   let left=0;for(let right=0;right<failures.length;right++){while(failures[right].t-failures[left].t>600000)left++;if(right-left>=4){findings.push({rule:'COR-001',severity:'high',description:`At least five authentication failure indicators in ten minutes (${g.kind}: ${g.value}); investigate`,evidence:failures.slice(left,right+1).map(x=>x.e.id)});break;}}
   if(g.kind==='sender'){const sent=g.events.filter(e=>/^(send|sent|delivered|submit)$/i.test(e.action)).map(e=>({e,t:Date.parse(e.timestamp)})).filter(x=>Number.isFinite(x.t)).sort((a,b)=>a.t-b.t);let l=0;for(let r=0;r<sent.length;r++){while(sent[r].t-sent[l].t>300000)l++;if(r-l>=49){findings.push({rule:'COR-002',severity:'medium',description:`High outbound activity indicator: ${g.value} (50 events in five minutes)`,evidence:sent.slice(l,r+1).map(x=>x.e.id)});break;}}}
  }
  // COR-003: Message trace - group events by Message ID (only when kind is message)
  if(g.kind==='message'){
   const messageGroups=new Map();for(const e of g.events){if(!e.message_id)continue;const k=e.message_id.trim();if(!messageGroups.has(k))messageGroups.set(k,[]);messageGroups.get(k).push(e);}for(const [msgId,msgEvents] of messageGroups){if(msgEvents.length>=3){findings.push({rule:'COR-003',severity:'medium',description:`Message trace reconstructed: ${msgId} has ${msgEvents.length} related events`,evidence:msgEvents.map(x=>x.e.id)})}}
  }
 }
 return {groups:[...groups.values()].filter(g=>g.events.length>1).sort((a,b)=>b.events.length-a.events.length),findings};
}
export function customFindings(events,rules){return rules.flatMap(r=>events.filter(e=>String(e[r.field]??'').toLowerCase().includes(r.contains.toLowerCase())).map(e=>({rule:r.id,severity:r.severity,description:r.description,evidence:[e.id]})));}
export function validateRules(rules){if(!Array.isArray(rules)||rules.length>100)throw Error('Expected up to 100 rules');const ids=new Set();for(const r of rules){if(!r||typeof r.id!=='string'||!r.id||ids.has(r.id)||!['sender','recipient','ip','action','message_id','source','timestamp'].includes(r.field)||typeof r.contains!=='string'||!r.contains.trim()||!['low','medium','high'].includes(r.severity)||typeof r.description!=='string')throw Error('Invalid rule or duplicate ID');ids.add(r.id);}return rules;}
export function batches(events){const result=[];let batch=[],n=2;for(const e of events){const bytes=new TextEncoder().encode(JSON.stringify(e)).length+1;if(bytes>99000)throw Error('Evidence record too large: '+e.id);if(batch.length>=25||n+bytes>99000){result.push(batch);batch=[];n=2;}batch.push(e);n+=bytes;}if(batch.length)result.push(batch);return result;}
export function htmlReport(report){const esc=x=>String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));return '<!doctype html><html lang="en"><meta charset="utf-8"><title>DFIR case report</title><style>body{font:15px system-ui;max-width:1000px;margin:40px auto}pre{white-space:pre-wrap;overflow-wrap:anywhere}td,th{padding:8px;border:1px solid #aaa}table{border-collapse:collapse;width:100%}</style><h1>DFIR case report</h1><p>Indicators and AI output require analyst verification.</p><h2>'+esc(report.name)+'</h2><p>'+esc(report.notes)+'</p><h2>Evidence manifest</h2><pre>'+esc(JSON.stringify(report.evidence.map(({events,...f})=>f),null,2))+'</pre><h2>Findings</h2><table><tr><th>Rule</th><th>Severity</th><th>Description</th><th>Evidence IDs</th></tr>'+report.findings.map(f=>'<tr><td>'+esc(f.rule)+'</td><td>'+esc(f.severity)+'</td><td>'+esc(f.description)+'</td><td>'+esc(f.evidence.join('\n'))+'</td></tr>').join('')+'</table><h2>AI output (unverified)</h2><pre>'+esc(report.ai_output_unverified)+'</pre></html>';}
