import {t} from './i18n.js';
import {findingKey,reviewFinding,feedbackMetrics} from './feedback.js';

export function mountReviewPanel({host,getState,save,status}) {
 const panel=document.createElement('article');panel.id='analystReview';panel.hidden=true;host.prepend(panel);
 let selected=null;
 const el=(tag,text)=>{const n=document.createElement(tag);if(text)n.textContent=text;return n;};
 function render(){
  if(!selected)return;const state=getState(),existing=state.feedback.find(x=>findingKey(x)===findingKey(selected));
  panel.replaceChildren();panel.append(el('h2',t('Analyst review')),el('p',selected.rule+' · '+selected.evidence.join(', ')));
  const label=el('label',t('Assessment'));const verdict=el('select');verdict.id='reviewVerdict';
  for(const value of ['supported','false_positive','insufficient']){const option=el('option',t(value));option.value=value;verdict.append(option);}
  verdict.value=existing?.verdict??'insufficient';label.append(verdict);
  const noteLabel=el('label',t('Reason and supporting evidence'));const note=el('textarea');note.id='reviewNote';note.rows=4;note.maxLength=2000;note.value=existing?.note??'';noteLabel.append(note);
  const commit=el('button',t('Save analyst review'));commit.id='saveAnalystReview';commit.className='primary';
  commit.onclick=()=>{try{const current=getState();if(!current.findings.some(f=>findingKey(f)===findingKey(selected)))throw Error('Finding no longer exists');save(reviewFinding(current.feedback,selected,verdict.value,note.value,current.events));panel.hidden=true;status('Review recorded. Save the case to preserve it.');}catch(error){status(String(error));}};
  const close=el('button',t('Cancel'));close.onclick=()=>panel.hidden=true;
  panel.append(label,noteLabel,el('p',t('Reviews are analyst judgments, not automatic labels. Notes remain in this case; only aggregate feedback is included in subsequent AI requests.')),commit,close);
 }
 return {open(finding){selected=finding;panel.hidden=false;render();panel.scrollIntoView({block:'start',behavior:'smooth'});},render,close(){panel.hidden=true;selected=null;},summary(){return feedbackMetrics(getState().feedback,getState().findings);}};
}
