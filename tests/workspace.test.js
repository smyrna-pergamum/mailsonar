import {test} from 'node:test';
import assert from 'node:assert/strict';
import {validateCase,prioritizeFindings} from '../src/case-state.js';
import {correlate,htmlReport} from '../src/analysis.js';
import {eventTime,timeQuality} from '../src/event-time.js';
import {catalog,t,setLocale,localizedQuestion} from '../src/i18n.js';
import {hourlyBuckets} from '../src/nightwire-data.js';

const event=(id,timestamp='2026-11-25T10:00:00Z')=>({id,timestamp,sender:'analyst@example.test',recipient:'',ip:'',message_id:'',action:'failed login',data:{}});
const saved=()=>({schema:'mail-dfir/1.0',evidence:[{source:'mail.log',sha256:'abc',warnings:[],events:[event('one')]}],iocs:[{type:'domain-name',value:'example.test'}],sigmaRules:[{id:'S1',detection:{condition:'selection',selection:{action:'failed login'}}}],mapping:{fields:{sender:'UserId'}},journal:[]});
test('case restore retains IOC, Sigma and parser settings without mutation',()=>{
 const c=saved(),snapshot=structuredClone(c),result=validateCase(c);
 assert.deepEqual(result.iocs,c.iocs);assert.deepEqual(result.sigmaRules,c.sigmaRules);assert.deepEqual(result.mapping,c.mapping);assert.deepEqual(c,snapshot);
});
test('case rejects duplicate IDs and malformed state before restoration',()=>{
 const c=saved();c.evidence[0].events.push(event('one'));assert.throws(()=>validateCase(c),/duplicate/);
 for(const patch of [{schema:'other'},{iocs:[null]},{sigmaRules:[{}]},{mapping:{fields:{id:'raw'}}},{journal:{}}])assert.throws(()=>validateCase({...saved(),...patch}));
});
test('case rejects record overflow',()=>{const c=saved();c.evidence[0].events=Array.from({length:100001},(_,i)=>event(String(i)));assert.throws(()=>validateCase(c),/100000/);});
test('timezone-free timestamps cannot silently use the workstation timezone',()=>{
 assert.ok(Number.isNaN(eventTime('2026-11-25T10:00:00')));
 assert.equal(eventTime('2026-11-25T11:00:00+01:00'),eventTime('2026-11-25T10:00:00Z'));
 const events=Array.from({length:5},(_,i)=>event(String(i),'2026-11-25T10:00:00'));
 assert.equal(correlate(events).findings.length,0);assert.deepEqual(hourlyBuckets(events),[]);
 assert.deepEqual(timeQuality([...events,event('missing','')]),{missing:1,ambiguous:5});
});
test('failure correlation inspects normalized action as well as raw fields',()=>{
 assert.equal(correlate(Array.from({length:5},(_,i)=>event(String(i)))).findings[0].rule,'COR-001');
});
test('normal message trace is informational, not a medium threat',()=>{
 const events=Array.from({length:3},(_,i)=>({...event(String(i)),action:'delivered',message_id:'m'}));
 assert.equal(correlate(events).findings[0].severity,'info');
});
test('findings deduplicate identical evidence sets and prioritize high severity',()=>{
 const low={rule:'X',description:'same',severity:'low',evidence:['b','a']};
 const high={rule:'Y',description:'other',severity:'high',evidence:['c']};
 const result=prioritizeFindings([low,{...low,evidence:['a','b','a']},high]);
 assert.equal(result.length,2);assert.equal(result[0].rule,'Y');assert.deepEqual(low.evidence,['b','a']);
});
test('all catalog entries have three languages and identical parameter contracts',()=>{
 for(const [key,values] of Object.entries(catalog))for(const lang of ['en','de','tr']){
  assert.ok(values[lang],`${lang}: ${key}`);
  assert.deepEqual([...values[lang].matchAll(/\{\w+\}/g)].map(x=>x[0]).sort(),[...key.matchAll(/\{\w+\}/g)].map(x=>x[0]).sort());
 }
});
test('localized messages preserve untrusted parameter values and unknown technical text',()=>{
 assert.equal(t('Imported {count} records.',{count:7},'tr'),'7 kayıt içe aktarıldı.');
 assert.equal(t('Parsing {path}',{path:'<raw>{count}'},'de'),'Verarbeite <raw>{count}');
 assert.equal(t('unknown technical error',{},'tr'),'unknown technical error');
});
test('AI response language retains evidence and schema instructions',()=>{
 try{setLocale('tr');assert.match(localizedQuestion('Inspect evt-1'),/Türkçe/);assert.match(localizedQuestion('Inspect evt-1'),/^Inspect evt-1/);assert.match(localizedQuestion('x'),/JSON keys/);assert.throws(()=>setLocale('xx'));}finally{setLocale('en');}
});
test('HTML report follows case language while escaping original content',()=>{
 const html=htmlReport({locale:'tr',name:'<script>',notes:'',evidence:[],findings:[],ai_output_unverified:''});
 assert.match(html,/<html lang="tr">/);assert.match(html,/DFIR vaka raporu/);assert.ok(!html.includes('<script>'));
});
