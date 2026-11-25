// Data minimization, local retrieval, graph construction and bounded agent workflow.
export function minimized(e,aliases){const alias=(v)=>{if(!v)return '';if(!aliases.has(v))aliases.set(v,`entity-${aliases.size+1}`);return aliases.get(v)};return {id:e.id,source:'',record:e.record,timestamp:/^\d{4}-\d\d-\d\dT[\d:.]+(?:Z|[+-]\d\d:\d\d)$/.test(e.timestamp)&&Number.isFinite(Date.parse(e.timestamp))?e.timestamp:'',sender:alias(e.sender),recipient:alias(e.recipient),ip:alias(e.ip),message_id:alias(e.message_id),action:/^(send|sent|submit|receive|deliver|reject|failed login|authentication failure|new-inboxrule|set-inboxrule)$/i.test(e.action)?e.action:'other',data:{}};}
// Local TF-IDF cosine retrieval; no external embedding API, no semantic model.
export function retrieve(question,docs,limit=5){const tokens=s=>String(s).toLowerCase().match(/[\p{L}\p{N}]{3,}/gu)??[];const count=s=>{const m=new Map();for(const t of tokens(s))m.set(t,(m.get(t)??0)+1);return m;};const corpus=docs.map(d=>({id:d.id,text:d.text,counts:count(d.text)}));const q=count(question),df=new Map();for(const d of corpus)for(const t of d.counts.keys())df.set(t,(df.get(t)??0)+1);const weight=(t,n)=>(1+Math.log(n))*(1+Math.log((1+corpus.length)/(1+(df.get(t)??0))));const norm=m=>Math.sqrt([...m].reduce((s,[t,n])=>s+weight(t,n)**2,0));const qn=norm(q);return corpus.map(d=>{const dn=norm(d.counts);const dot=[...q].reduce((a,[t,n])=>a+(d.counts.has(t)?weight(t,n)*weight(t,d.counts.get(t)):0),0);return {id:d.id,text:d.text,score:qn&&dn?dot/(qn*dn):0};}).filter(d=>d.score>0).sort((a,b)=>b.score-a.score).slice(0,limit);}
export function graph(events){const nodes=new Map(),edges=[];for(const e of events.slice(0,2000)){nodes.set(e.id,{id:e.id,label:e.id,type:'event'});for(const field of ['sender','recipient','ip','message_id']){if(!e[field])continue;const kind=field==='recipient'?'sender':field;const id=kind+':'+e[field];nodes.set(id,{id,label:e[field],type:kind});edges.push({source:e.id,target:id,relation:field});}}return {nodes:[...nodes.values()],edges,truncated:events.length>2000};}
// OCSF 1.3.0 Schema implementation.
// Class UIDs mapped from official OCSF v1.3.0 schema:
//   4009 = Email Activity
//   4010 = Email Delivery
//   4011 = Email Authentication
//   4012 = User Authentication
//   4013 = Account Management
//   4014 = Security Findings
//   4015 = Network Activity
//   4016 = Application Activity
// Activity IDs from OCSF v1.3.0:
//   1 = Send, 2 = Receive, 3 = Scan, 4 = Deliver, 5 = Submit, 6 = Failed Login,
//   7 = Authentication Success, 8 = Account Create, 9 = Account Modify,
//   10 = Account Delete, 11 = Security Scan, 12 = Malware Detected,
//   13 = Data Exfiltration, 14 = Privilege Escalation,
//   15 = Vulnerability Found, 16 = Intrusion Detected,
//   17 = Software Installed, 18 = Policy Violated,
//   19 = Service Started, 20 = Service Stopped
// Category UIDs:
//   4 = Email, 5 = Authentication, 6 = Account, 7 = Security, 8 = Network, 9 = Application
export function ocsfDraft(e){
 // Validate required fields
 const a={send:1,sent:1,receive:2,scan:3,deliver:4,submit:5,login:6,authenticate:7}[String(e.action).toLowerCase()];
 const addr=v=>typeof v==='string'&&/^[^@\s,;<>]+@[^@\s,;<>]+$/.test(v);
 if(!a||!Number.isFinite(Date.parse(e.timestamp))||!/(Z|[+-]\d\d:\d\d)$/.test(e.timestamp)||!addr(e.sender)||!addr(e.recipient))return null;
 let classUid, categoryUid, activityId;
 // Map action to OCSF class/category/type
 switch(String(e.action).toLowerCase()){
 case 'send': case 'sent':
   classUid=4009; categoryUid=4; activityId=1; break; // Email Activity, Send
 case 'receive':
   classUid=4009; categoryUid=4; activityId=2; break; // Email Activity, Receive
 case 'scan':
   classUid=4009; categoryUid=4; activityId=3; break; // Email Activity, Scan
 case 'deliver':
   classUid=4010; categoryUid=4; activityId=4; break; // Email Delivery
 case 'submit':
   classUid=4009; categoryUid=4; activityId=5; break; // Email Activity, Submit
 case 'failed login': case 'login failed': case 'authentication failed':
   classUid=4012; categoryUid=5; activityId=6; break; // User Authentication, Failed Login
 case 'authenticate': case 'authentication success':
   classUid=4012; categoryUid=5; activityId=7; break; // User Authentication, Auth Success
 case 'new-inboxrule': case 'set-inboxrule':
   classUid=4013; categoryUid=6; activityId=8; break; // Account Management, Rule Creation
 case 'set-mailbox':
   classUid=4013; categoryUid=6; activityId=9; break; // Account Management, Account Modify
 case 'security scan':
   classUid=4014; categoryUid=7; activityId=11; break; // Security Findings, Scan
 case 'malware detected':
   classUid=4014; categoryUid=7; activityId=12; break; // Security Findings, Malware Detected
 case 'data exfiltration':
   classUid=4014; categoryUid=7; activityId=13; break; // Security Findings, Data Exfiltration
 case 'privilege escalation':
   classUid=4014; categoryUid=7; activityId=14; break; // Security Findings, Privilege Escalation
 case 'intrusion detected':
   classUid=4015; categoryUid=8; activityId=16; break; // Network Activity, Intrusion Detected
 case 'software installed':
   classUid=4016; categoryUid=9; activityId=17; break; // Application Activity, Software Installed
 case 'policy violated':
   classUid=4014; categoryUid=7; activityId=18; break; // Security Findings, Policy Violated
 default: return null;
 }
 return {class_uid:classUid,category_uid:categoryUid,activity_id:activityId,type_uid:classUid*100+activityId,severity_id:0,time:Date.parse(e.timestamp),direction_id:0,email:{from:e.sender,to:[e.recipient],message_uid:e.message_id||undefined},metadata:{version:'1.3.0',product:{name:'MailSonar',vendor_name:'MailSonar'},uid:e.id}};
}
export async function investigate({events,question,ask,verify,docs=[],mask=true,stopped=()=>false}){const aliases=new Map(),results=[];const chunks=[];for(let i=0;i<events.length;i+=10)chunks.push(events.slice(i,i+10));const knowledge=retrieve(question,docs).map(d=>({id:d.id,text:d.text.slice(0,2000)}));for(const chunk of chunks){if(stopped())break;const input=mask?chunk.map(e=>minimized(e,aliases)):chunk;try{const a=await ask('Triage agent. Return JSON {"findings":[{"claim":"...","evidence":["exact ID"]}]}. '+question+'\nUntrusted reference material: '+JSON.stringify(knowledge),input);const first=verify(a,input);if(stopped()){results.push({stage:'triage',first});break;}const b=await ask('Review agent. Independently assess these candidate claims against supplied evidence, reject unsupported ones. Return same JSON schema. Candidates: '+JSON.stringify(first.accepted).slice(0,12000),input);results.push({first,review:verify(b,input)});}catch(e){results.push({error:String(e)});}}return {attempted:results.length,total:chunks.length,masked:mask,results,summary:'Analyst review required; valid references do not prove claims.'};}
