// Analyst-reviewed case memory. Never train on an AI answer automatically.
export const VERDICTS = ['supported','false_positive','insufficient'];
export function findingKey(finding) {
 return JSON.stringify([finding.rule,[...new Set(finding.evidence)].sort()]);
}
export function validateFeedback(input, events) {
 if (!Array.isArray(input) || input.length>20000) throw Error('Invalid feedback collection');
 const ids=new Set(events.map(e=>e.id)),keys=new Set();
 return input.map(row=>{
  if(!row||row.version!==1||typeof row.rule!=='string'||row.rule.length>128||!VERDICTS.includes(row.verdict)||typeof row.note!=='string'||!row.note.trim()||row.note.length>2000||!Array.isArray(row.evidence)||!row.evidence.length||row.evidence.some(id=>!ids.has(id))||!Number.isFinite(Date.parse(row.updated_at)))throw Error('Invalid analyst feedback');
  const key=findingKey(row);if(keys.has(key))throw Error('Duplicate feedback');keys.add(key);
  return {...row,key};
 });
}
export function reviewFinding(memory, finding, verdict, note, events) {
 const row={version:1,rule:finding.rule,evidence:[...new Set(finding.evidence)],verdict,note:String(note).trim(),updated_at:new Date().toISOString()};
 const next=[...memory.filter(item=>findingKey(item)!==findingKey(row)),row];
 return validateFeedback(next,events);
}
export function feedbackContext(memory, findings) {
 const current=new Set(findings.map(findingKey)),counts=new Map();
 for(const row of memory){
  if(!current.has(findingKey(row)))continue;
  // Custom IDs can contain private text. Only built-in identifiers leave the case.
  const rule=/^(?:MAIL|COR|ANOM|TI)-\d{3}$/.test(row.rule)?row.rule:'CUSTOM';
  if(!counts.has(rule))counts.set(rule,{rule,supported:0,false_positive:0,insufficient:0});
  counts.get(rule)[row.verdict]++;
 }
 if(!counts.size)return '';
 return '\nAnalyst feedback from this case (aggregate counts only; not proof about other events): '+JSON.stringify([...counts.values()].slice(0,40))+
 '\nRecheck the source evidence independently. Explain benign alternatives and missing evidence. Do not suppress a finding solely because a similar rule was marked false positive. Do not treat prior model output as ground truth.';
}
export function feedbackMetrics(memory, findings) {
 const keys=new Set(findings.map(findingKey));
 const active=memory.filter(row=>keys.has(findingKey(row)));
 return {reviewed:active.length,supported:active.filter(x=>x.verdict==='supported').length,false_positive:active.filter(x=>x.verdict==='false_positive').length,insufficient:active.filter(x=>x.verdict==='insufficient').length,stale:memory.length-active.length};
}
