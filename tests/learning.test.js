import {test} from 'node:test';
import assert from 'node:assert/strict';
import {reviewFinding,feedbackContext,validateFeedback,feedbackMetrics} from '../src/feedback.js';
import {prepareTraining} from '../src/training.js';
import {ruleTemplates,previewRule,smartTask} from '../src/rules-workbench.js';
import {reportAnalysis} from '../src/report-data.js';
const events=[{id:'e1',timestamp:'2026-11-25T10:00:00Z',sender:'alice@example.test',recipient:'bob@example.test',ip:'192.0.2.1',action:'new-inboxrule',message_id:'msg-1',data:{UserId:'alice@example.test',Operation:'new-inboxrule',raw:'SECRET RAW CONTENT'},record:1}];
const finding={rule:'MAIL-002',severity:'high',description:'review',evidence:['e1']};
test('review updates a finding without creating duplicate training labels',()=>{
 let memory=reviewFinding([],finding,'supported','Evidence supports this rule change.',events);
 memory=reviewFinding(memory,finding,'false_positive','Authorized administrator change verified.',events);
 assert.equal(memory.length,1);assert.equal(memory[0].verdict,'false_positive');assert.equal(feedbackMetrics(memory,[finding]).reviewed,1);
 assert.throws(()=>reviewFinding(memory,finding,'yes','reason',events));assert.throws(()=>reviewFinding([],finding,'supported','',events));
 assert.throws(()=>validateFeedback([{...memory[0],evidence:['missing']}],events));
});
test('AI feedback context includes aggregate judgments, never notes or identifiers',()=>{
 const memory=reviewFinding([],finding,'false_positive','alice@example.test authorized secret value',events);
 const context=feedbackContext(memory,[finding]);assert.match(context,/false_positive/);assert.ok(!context.includes('alice'));assert.ok(!context.includes('secret'));assert.ok(!context.includes('e1'));
 assert.equal(feedbackContext(memory,[]),'');
});
test('training uses analyst targets and minimized context; uncertainty is excluded',()=>{
 const feedback=reviewFinding([],finding,'supported','alice@example.test changed the rule; source evidence reviewed.',events);
 const result=prepareTraining({events,findings:[finding],feedback});assert.equal(result.examples.length,1);
 assert.ok(!result.jsonl.includes('SECRET RAW CONTENT'));assert.ok(!result.jsonl.includes('alice@example.test'));
 const example=JSON.parse(result.jsonl.trim());assert.deepEqual(example.messages.map(x=>x.role),['system','user','assistant']);
 assert.equal(JSON.parse(example.messages[2].content).assessment,'supported');
 assert.equal(prepareTraining({events,findings:[],feedback}).examples.length,0);
 const uncertain=reviewFinding([],finding,'insufficient','We need more evidence before deciding.',events);
 assert.equal(prepareTraining({events,findings:[finding],feedback:uncertain}).examples.length,0);
});
test('training excludes short rationale and oversized context rather than silently truncating',()=>{
 const feedback=reviewFinding([],finding,'supported','short',events);
 assert.equal(prepareTraining({events,findings:[finding],feedback}).skipped,1);
 const many=Array.from({length:26},(_,i)=>({...events[0],id:'e'+i}));const f={...finding,evidence:many.map(e=>e.id)};
 const reviews=reviewFinding([],f,'supported','Long enough analyst explanation for this assessment.',many);
 assert.equal(prepareTraining({events:many,findings:[f],feedback:reviews}).skipped,1);
});
test('all shipped templates validate; preview is non-mutating',()=>{
 const snapshot=structuredClone(events);
 for(const template of ruleTemplates)assert.ok(Array.isArray(previewRule(template.kind,template.value,events)));
 assert.deepEqual(events,snapshot);assert.match(smartTask(),/evidence_inspect/);assert.match(smartTask('takeover'),/account takeover/);assert.throws(()=>smartTask('unknown'));
});
test('report visual data derives counts and bounded links from the case',()=>{
 const more=[...events,{...events[0],id:'e2',timestamp:''}];const report=reportAnalysis(more,[finding]);
 assert.equal(report.events,2);assert.equal(report.dated,1);assert.equal(report.time_quality.missing,1);assert.equal(report.severity[0].count,1);
 assert.equal(report.timeline[0][1],1);assert.ok(report.relationships.every(x=>x.evidence.every(id=>['e1','e2'].includes(id))));
});
