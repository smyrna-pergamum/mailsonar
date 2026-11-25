import {test} from 'node:test';import assert from 'node:assert/strict';import {correlate,validateRules,customFindings,batches,htmlReport} from '../src/analysis.js';
const events=Array.from({length:5},(_,i)=>({id:String(i),sender:'a@example.test',ip:'192.0.2.1',message_id:'',timestamp:new Date(1700000000000+i*1000).toISOString(),action:'failure',data:{message:'failed login'}}));
test('correlation links five failures',()=>assert.equal(correlate(events).findings.length,2));
test('missing time does not trigger window',()=>assert.equal(correlate(events.map(e=>({...e,timestamp:''}))).findings.length,0));
test('custom rules validate and match',()=>{const r=validateRules([{id:'X',field:'sender',contains:'example',severity:'low',description:'test'}]);assert.equal(customFindings(events,r).length,5);assert.throws(()=>validateRules([{id:'X'}]));});
test('batch coverage and limits',()=>{const e=Array.from({length:61},(_,i)=>({...events[0],id:String(i)}));const b=batches(e);assert.deepEqual(b.flat(),e);assert.ok(b.every(x=>x.length<=25));});
test('HTML escapes untrusted text',()=>{const h=htmlReport({name:'<script>alert(1)</script>',notes:'',evidence:[],findings:[],ai_output_unverified:'<img>'});assert.ok(!h.includes('<script>'));assert.ok(!h.includes('<img>'));});
