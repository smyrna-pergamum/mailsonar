import {mountTraining} from './training.js';
import {feedbackContext,findingKey} from './feedback.js';
import {reportAnalysis} from './report-data.js';
import {mountRulesWorkbench,smartTask} from './rules-workbench.js';
import {mountReviewPanel} from './review-panel.js';
import {t,getLocale,mountLocale,localizedQuestion} from './i18n.js';
import {validateCase,prioritizeFindings} from './case-state.js';
import {eventTime,timeQuality} from './event-time.js';
import {privateGateway,graphNeighborhood} from './privacy.js';
import {investigate,graph,ocsfDraft} from './investigation.js';
import {normalize,iocsFrom,matchIocs,sigmaSubset,anomaly,trace,verifyAi,attackTags,parsePlugin} from './advanced.js';
import {correlate,customFindings,validateRules,batches,htmlReport} from './analysis.js';
import {invoke} from '@tauri-apps/api/core';
import {open,save} from '@tauri-apps/plugin-dialog';
import './style.css';
import './nightwire.css';
import './workspace.css';
import {initTheme,preferredTheme,renderDashboard,renderTimeline,renderGraph,renderMitre,renderThreatIntel,renderAiEvaluation,resizeCharts} from './nightwire.js';
import {mountCopilot} from './assistant.js';
import {mountBeacon} from './beacon/panel.js';
import {killChains} from './killchain.js';
import {bindLegacyFields} from './ui/provider.js';
import {organizeNav,foldAdvanced} from './ui/nav.js';
import {mountHome} from './ui/home.js';
import {mountEmailView} from './ui/email-view.js';
import {mountQuickAi,PROFILES} from './ui/quick-ai.js';
import {mountRuleAi} from './ui/rule-ai.js';
import {mountModelHub} from './ui/model-hub.js';
import {mountAcademy} from './ui/academy.js';
import {mountAdvancedAi} from './ui/advanced-ai.js';
import {mountGraphFilters} from './ui/graph-filters.js';
import {mountLargeCases} from './ui/large-cases.js';
import {registerStrings} from './ui/strings.js';
import './ui/simple.css';
registerStrings();
document.documentElement.dataset.theme=preferredTheme();
const root=document.querySelector('#app');
root.innerHTML=`<aside><div class="brand"><img src="/mailsonar-mark.svg" alt="MailSonar emblem"><div>MAIL<span>SONAR</span></div><small>DETECT THREATS BENEATH THE SURFACE</small></div><nav><button data-tab="dashboard">Overview</button><button data-tab="explorer">Log explorer</button><button data-tab="findings">Findings</button><button data-tab="evidence">Evidence</button><button data-tab="ai">AI investigator</button><button data-tab="case">Case management</button><button data-tab="timeline">Timeline & correlation</button><button data-tab="rules">Developer rules</button><button data-tab="settings">AI settings</button></nav><div class="foot">MAILSONAR &middot; v1.3<br>Detect threats beneath the surface</div></aside><main><header><div><small>DIGITAL FORENSICS & INCIDENT RESPONSE</small><h1 id="title">Overview</h1></div><div><button id="import" class="primary">+ Import evidence</button> <button id="export">Export case</button></div></header><div id="status" role="status">Ready. No AI model required.</div><section id="dashboard" class="tab"><div class="metrics" id="metrics"></div><article><h2>Investigation workflow</h2><p>Import log files, inspect normalized records, review rule-based findings and select evidence for AI-assisted investigation.</p><p>Evidence stays on this device unless you explicitly send selected records to a configured AI endpoint.</p></article><article><h2>Recent findings</h2><div id="recent"></div></article></section><section id="explorer" class="tab" hidden><div class="toolbar"><input id="search" placeholder="Search all event fields"><button id="prev">Previous</button><span id="page"></span><button id="next">Next</button><button id="selectpage">Select visible (max 25)</button><button id="clearselect">Clear selection</button></div><div class="tablewrap"><table><thead><tr><th></th><th>Time (source)</th><th>Source</th><th>Sender / user</th><th>Recipient</th><th>Action</th><th>Record</th></tr></thead><tbody id="rows"></tbody></table></div><article><h2>Record detail</h2><pre id="detail">Select a record.</pre></article></section><section id="findings" class="tab" hidden><article><h2>Rule-based triage</h2><p>Indicators are not confirmed incidents. Review source evidence.</p><div id="findinglist"></div></article></section><section id="evidence" class="tab" hidden><article><h2>Imported evidence</h2><div id="files"></div></article></section><section id="ai" class="tab" hidden><article><h2>Evidence-grounded AI investigation</h2><p id="selected"></p><p>Select up to 25 records in Log explorer. All AI actions send minimized records only, but your question and reference notes are transmitted as entered. Do not include secrets or personal data. Batch analysis covers all imported records.</p><textarea id="question" rows="4">Investigate the selected records. Identify suspicious indicators, cite exact evidence IDs, and recommend next investigative steps.</textarea><label class="consent"><input type="checkbox" id="consent"> I authorize sending the records for the chosen action and the question to the configured endpoint.</label><button id="batch" class="primary">Analyze all records in batches</button> <button id="cancelBatch">Stop after current request</button><button id="ask" class="primary">Analyze selected evidence</button><pre id="answer">AI output will appear here. Verify all claims against the original records.</pre></article></section><section id="settings" class="tab" hidden><article><h2>OpenAI-compatible API</h2><p>Use a local llama.cpp server, LM Studio, Ollama compatibility endpoint, private server or cloud provider. Settings and key are session-only.</p><label>Provider preset<select id="preset"><option value="">Custom</option><option value="http://127.0.0.1:8080/v1/chat/completions">llama.cpp</option><option value="http://127.0.0.1:1234/v1/chat/completions">LM Studio</option><option value="http://127.0.0.1:11434/v1/chat/completions">Ollama</option><option value="https://api.openai.com/v1/chat/completions">OpenAI</option><option value="https://openrouter.ai/api/v1/chat/completions">OpenRouter</option></select></label><label>Full chat completions endpoint<input id="endpoint" type="url" value="http://127.0.0.1:8080/v1/chat/completions"></label><label>Model identifier<input id="model" placeholder="Exact model name from provider"></label><label>API key (if required)<input type="password" id="key" autocomplete="off"></label><p>HTTPS is required for remote endpoints. Local loopback HTTP is supported.</p></article></section><section id="case" class="tab" hidden><article><h2>Case workspace</h2><label>Case name<input id="caseName" value="Untitled investigation"></label><label>Analyst notes<textarea id="caseNotes"></textarea></label><button id="saveCase">Save case</button> <button id="loadCase">Open saved case</button> <button id="newCase">New case</button> <button id="htmlReport">Export HTML / print to PDF</button><h3>Activity journal (not tamper-proof)</h3><pre id="journal"></pre></article></section><section id="timeline" class="tab" hidden><article><h2>Event timeline</h2><p>Only timestamps with an explicit timezone are used for time-window correlation.</p><div id="timelineChart"></div><div id="timelineRows"></div><h2>Shared entity groups</h2><p>Shared identifiers are investigative leads, not proof of causation.</p><div id="groups"></div></article></section><section id="rules" class="tab" hidden><article><h2>Developer mode: custom detection rules</h2><p>JSON field-contains rules, not full Sigma compatibility.</p><textarea id="rulesInput" rows="12">[]</textarea><button id="applyRules">Validate & apply</button></article></section></main>`;
const nwNav=document.querySelector('aside nav');
for(const [id,label] of [['graph','Relationship graph'],['mitre','MITRE ATT&CK'],['ti','Threat intelligence'],['eval','AI evaluation']]){const b=document.createElement('button');b.dataset.tab=id;b.textContent=label;nwNav.append(b);}
const nwMain=document.querySelector('main');
const nwSections={graph:'',mitre:`<article><h2>MITRE ATT&amp;CK matrix</h2><p>Heuristic mapping from detection rules to ATT&amp;CK techniques. Counts are computed from current findings; empty cells are not evidence of absence.</p><div id="mitreMatrix" class="mitre-matrix"></div><div id="mitreDetail"></div></article>`,ti:`<article><h2>Threat intelligence</h2><p>Loaded indicators and local matches. No external enrichment is performed.</p><div id="tiVisual"></div><div id="tiTable"></div></article>`,eval:`<article><h2>AI evaluation center</h2><p>Session metrics are measured from this workspace. Quality benchmarks without a labeled dataset are reported as Not Evaluated.</p><div id="aiEval"></div></article>`};
for(const [id,html] of Object.entries(nwSections)){const s=document.createElement('section');s.id=id;s.className='tab';s.hidden=true;s.innerHTML=html;nwMain.append(s);}
const nwTheme=document.createElement('button');nwTheme.id='themeToggle';nwTheme.className='theme-toggle';nwTheme.type='button';nwTheme.textContent='Light theme';nwNav.after(nwTheme);
const extraRenderers=[];const $=id=>document.getElementById(id);let rules=[],journal=[],baseFindings=[],cancelled=false, evidence=[],events=[],findings=[],selected=new Set(),page=0,busy=false,aiAnswer='',aiRuns=[];const size=50; let iocs=[],sigmaRules=[],mapping=null,copilot=null;let correlationResult={groups:[],findings:[]},hourFilter=null,feedback=[],reviewPanel=null,rulesWorkbench=null,trainingPanel=null;
function el(tag,txt,cls){const n=document.createElement(tag);if(txt!==undefined)n.textContent=txt;if(cls)n.className=cls;return n;}
let lastStatus=['Ready. No AI model required.',{}];const operations=[];
function status(s,params={}){lastStatus=[s,params];$('status').textContent=t(s,params);operations.push({time:new Date().toISOString(),key:s,params});if(operations.length>200)operations.shift();renderOperations();}
function renderOperations(){const out=$('operationLog');if(!out)return;out.replaceChildren();for(const entry of [...operations].reverse()){out.append(el('li',entry.time+' · '+t(entry.key,entry.params)));}}
// Single backend entry point used by BEACON. In the browser preview it is
// backed by the DEV-only synthetic mock; production always uses Tauri IPC.
async function backend(name,args){if(window.__TAURI_INTERNALS__)return invoke(name,args);if(import.meta.env.DEV&&typeof window.__maildfirMock==='function')return window.__maildfirMock(name,args);throw Error('The MailSonar desktop backend is unavailable in this preview.');}
function tab(id){document.querySelectorAll('.tab').forEach(n=>n.hidden=n.id!==id);document.querySelectorAll('nav button').forEach(n=>(n.classList.toggle('active',n.dataset.tab===id),n.setAttribute('aria-current',n.dataset.tab===id?'page':'false')));const active=document.querySelector(`nav [data-tab="${id}"]`);$('title').textContent=active?active.textContent:'Overview';resizeCharts();renderAnalysisPanels();$(id)?.dispatchEvent(new Event('ms:shown'));}
document.querySelectorAll('nav button').forEach(n=>n.onclick=()=>tab(n.dataset.tab));tab('dashboard');
function listFindings(id,items){if(id==='findinglist'&&$('severityFilter')?.value)items=items.filter(f=>f.severity===$('severityFilter').value);const c=$(id);c.replaceChildren();if(!items.length)c.append(el('p','No findings. This does not establish absence of compromise.'));for(const f of items){const row=el('div',undefined,'finding');row.append(el('b',f.severity.toUpperCase(),'severity '+f.severity),el('span',`${f.rule} · ${t(f.description)}`));const btn=el('button','Inspect');btn.onclick=()=>{const related=events.filter(x=>f.evidence.includes(x.id));if(related.length){tab('explorer');$('detail').textContent=JSON.stringify(related,null,2);}};row.append(btn);const review=el('button',t('Analyst review'));review.onclick=()=>{tab('findings');reviewPanel?.open(f);};row.append(review);const assessment=feedback.find(x=>findingKey(x)===findingKey(f));if(assessment)row.append(el('small',t(assessment.verdict)));c.append(row);}}
function filtered(){const q=$('search').value.toLowerCase();return events.filter(e=>(!q||JSON.stringify(e).toLowerCase().includes(q))&&(hourFilter===null||Math.floor(eventTime(e.timestamp)/3600000)===hourFilter));}
function renderRows(){const a=filtered();page=Math.min(page,Math.max(0,Math.ceil(a.length/size)-1));$('page').textContent=`${page+1} / ${Math.max(1,Math.ceil(a.length/size))} · ${t('{count} records',{count:a.length})}`;$('rows').replaceChildren();for(const e of a.slice(page*size,(page+1)*size)){const tr=el('tr');const td=el('td');const cb=el('input');cb.type='checkbox';cb.checked=selected.has(e.id);cb.onchange=()=>{if(cb.checked&&selected.size>=25){cb.checked=false;status('Maximum 25 selected records.');return;}cb.checked?selected.add(e.id):selected.delete(e.id);updateSelection();};td.append(cb);tr.append(td);for(const v of [e.timestamp,e.source,e.sender,e.recipient,e.action])tr.append(el('td',v||'—'));const cell=el('td');const btn=el('button',`#${e.record}`);btn.onclick=()=>{$('detail').textContent=JSON.stringify(e,null,2);};cell.append(btn);tr.append(cell);$('rows').append(tr);}}
function updateSelection(){$('selected').textContent=t('{count} of 25 evidence records selected.',{count:selected.size});$('consent').checked=false;}
function render(){const m=$('metrics');m.replaceChildren();for(const [l,v] of [['Evidence files',evidence.length],['Events',events.length],['Findings',findings.length],['High-priority indicators',findings.filter(f=>f.severity==='high').length]]){const n=el('div',undefined,'metric');n.append(el('small',l),el('strong',String(v)));m.append(n);}listFindings('recent',findings.slice(0,8));listFindings('findinglist',findings);$('files').replaceChildren();for(const f of evidence){const n=el('div',undefined,'file');n.append(el('h3',f.source),el('p',`${f.bytes} bytes · ${f.events.length} records`),el('code',`SHA-256: ${f.sha256}`));for(const w of f.warnings)n.append(el('p',w,'warning'));$('files').append(n);}renderRows();updateSelection();renderExtra();renderCyber();if($('graphRefresh')&&events.length){currentGraph=graph(events);fillGraphNodes();}renderAnalysisPanels();copilot?.refreshCase();renderQuality();for(const fn of extraRenderers)fn();}
async function importPaths(paths,label='Import'){const errors=[];for(const path of paths){try{status('Parsing {path}',{path});const f=await backend('import_file',{path});if(evidence.some(x=>x.sha256===f.sha256)){errors.push(`${f.source}: duplicate hash skipped`);continue;}if(events.length+f.events.length>100000){errors.push(`${f.source}: workspace limit of 100,000 records exceeded - use Large investigations`);continue;}await backend('preserve',{path,expected:f.sha256});f.events=f.events.map(normalize).map(e=>mapping?parsePlugin(e,mapping):e);evidence.push(f);events.push(...f.events);}catch(e){errors.push(String(e));}}baseFindings=await backend('analyze',{events});journal.push({time:new Date().toISOString(),action:label,details:paths.length+" files"});refreshFindings();render();errors.length?status(errors.join(' | ')):status('Imported {count} records.',{count:events.length});return errors;}
$('import').onclick=async()=>{if(busy)return;busy=true;$('import').disabled=true;try{const paths=await open({multiple:true,filters:[{name:'Evidence files',extensions:['csv','json','jsonl','xml','txt','log','eml','mbox','mbx','msg','evtx','zip','gz','gzip','xlsx']}]});if(paths)await importPaths(paths);}catch(e){status(String(e));}finally{busy=false;$('import').disabled=false;}};
$('search').oninput=()=>{hourFilter=null;page=0;renderRows()};$('prev').onclick=()=>{page=Math.max(0,page-1);renderRows()};$('next').onclick=()=>{page++;renderRows()};$('selectpage').onclick=()=>{for(const e of filtered().slice(page*size,(page+1)*size)){if(selected.size>=25)break;selected.add(e.id);}renderRows();updateSelection()};$('clearselect').onclick=()=>{selected.clear();renderRows();updateSelection()};$('preset').onchange=()=>{if($('preset').value)$('endpoint').value=$('preset').value;$('consent').checked=false;};for(const id of ['endpoint','model','key','question'])$(id).oninput=()=>{$('consent').checked=false;};
$('ask').onclick=async()=>{if(busy||!$('consent').checked||!selected.size){status('Select evidence and authorize the request first.');return;}const endpoint=$('endpoint').value,model=$('model').value,key=$('key').value,question=$('question').value;const chosen=events.filter(e=>selected.has(e.id));busy=true;$('ask').disabled=true;$('consent').checked=false;const started=performance.now();try{status('Waiting for AI endpoint response...');aiAnswer=await privateGateway(backend,{endpoint,model,key})(question+feedbackContext(feedback,findings),chosen);$('answer').textContent=aiAnswer;const validation=verifyAi(aiAnswer,chosen);let jsonValid=false;try{JSON.parse(aiAnswer);jsonValid=true;}catch{}recordAiRun({mode:'selected evidence',model,host:aiHost(endpoint),events:chosen.length,ms:performance.now()-started,ok:true,validation,jsonValid});status('AI analysis received; analyst verification required.');}catch(e){recordAiRun({mode:'selected evidence',model,host:aiHost(endpoint),events:chosen.length,ms:performance.now()-started,ok:false,error:String(e)});status(String(e));}finally{busy=false;$('ask').disabled=false;}};
$('export').onclick=async()=>{try{const path=await save({defaultPath:'mail-dfir-case.json',filters:[{name:'JSON report',extensions:['json']}]});if(!path)return;await invoke('export_report',{path,report:caseData()});status('Case report exported.');}catch(e){status(String(e));}};
function caseData(){return {schema:'mail-dfir/1.0',exported_at:new Date().toISOString(),name:$('caseName').value,notes:$('caseNotes').value,evidence,findings,rules,journal,iocs,sigmaRules,ai_output_unverified:aiAnswer,mapping,feedback,analysis:reportAnalysis(events,findings,feedback),locale:getLocale()};}
function refreshFindings(){correlationResult=correlate(events);const base=[...baseFindings,...correlationResult.findings,...customFindings(events,rules),...matchIocs(events,iocs),...anomaly(events),...sigmaRules.flatMap(r=>sigmaSubset(events,r))];findings=prioritizeFindings([...base,...killChains(events,base)]).map(f=>({...f,attack:attackTags(f)}));}
function renderExtra(){const t=$('timelineRows');t.replaceChildren();const timed=events.filter(e=>Number.isFinite(eventTime(e.timestamp))).sort((a,b)=>eventTime(a.timestamp)-eventTime(b.timestamp));t.append(el('p',`${timed.length} dated records; showing first 500. ${events.length-timed.length} unparsed/missing timestamps.`));for(const e of timed.slice(0,500)){const b=el('button',`${e.timestamp} | ${e.action} | ${e.sender}`);b.onclick=()=>{tab('explorer');$('detail').textContent=JSON.stringify(e,null,2)};t.append(b,el('br'));}const g=$('groups');g.replaceChildren();for(const x of correlationResult.groups.slice(0,200)){const d=el('details');d.append(el('summary',`${x.kind}: ${x.value} (${x.events.length})`));for(const e of x.events.slice(0,50)){const b=el('button',`${e.source} #${e.record}`);b.onclick=()=>{tab('explorer');$('detail').textContent=JSON.stringify(e,null,2)};d.append(b);}g.append(d);} $('journal').textContent=JSON.stringify(journal,null,2);}
function aiHost(endpoint){try{return new URL(endpoint).host;}catch{return 'invalid endpoint';}}
function recordAiRun(run){aiRuns.push({time:new Date().toISOString(),...run});if(!$('eval').hidden)renderEvalPanel();}
function renderCyber(){let panel=$('cyberDashboard');if(!panel){panel=el('div',undefined,'cyber-grid');panel.id='cyberDashboard';$('metrics').after(panel);}renderDashboard(panel,{events,findings});}
function renderTimelinePanel(){const host=$('timelineChart');if(!host)return;renderTimeline(host,events,ts=>{tab('explorer');$('search').value='';hourFilter=Math.floor(eventTime(ts)/3600000);page=0;renderRows();status('Filtered to {time} (UTC hour).',{time:ts});});}
function renderMitrePanel(){const host=$('mitreMatrix');if(!host)return;renderMitre(host,findings);host.querySelectorAll('.mitre-cell').forEach(btn=>btn.onclick=()=>{const id=btn.dataset.technique;const rows=findings.filter(f=>(f.attack||[]).some(t=>t.split('.')[0]===id));const out=$('mitreDetail');out.replaceChildren(el('h3',`${id} - ${rows.length} findings`));if(!rows.length)out.append(el('p','No current findings map to this technique.'));else for(const f of rows.slice(0,100)){const b=el('button',`${f.rule} - ${f.severity} - ${f.description}`);b.onclick=()=>{const related=events.filter(x=>f.evidence.includes(x.id));if(related.length){tab('explorer');$('detail').textContent=JSON.stringify(related,null,2);}};out.append(b,el('br'));}});}
function renderTiPanel(){const host=$('tiVisual');if(!host)return;renderThreatIntel(host,$('tiTable'),{iocs,findings});}
function renderEvalPanel(){const host=$('aiEval');if(!host)return;renderAiEvaluation(host,{runs:aiRuns,model:$('model').value,endpoint:$('endpoint').value,answer:aiAnswer});}
function renderGraphPanel(){if(!currentGraph.nodes.length&&events.length)currentGraph=graph(events);fillGraphNodes();}
function renderAnalysisPanels(){if(!$('timeline').hidden)renderTimelinePanel();if(!$('mitre').hidden)renderMitrePanel();if(!$('ti').hidden)renderTiPanel();if(!$('eval').hidden)renderEvalPanel();if(!$('graph').hidden)renderGraphPanel();}
$('applyRules').onclick=()=>{try{rules=validateRules(JSON.parse($('rulesInput').value));refreshFindings();render();status('Custom rules applied.');}catch(e){status(String(e));}};
$('saveCase').onclick=async()=>{try{await invoke('store_case',{id:$('caseName').value,body:caseData()});status('Case saved in SQLite. Use Export case for JSON.');}catch(e){status(String(e));}};
async function restoreCase(input){
 const c=validateCase(input),ev=c.evidence.flatMap(f=>f.events);
 const bf=await invoke('analyze',{events:ev});
 evidence=c.evidence;events=ev;rules=c.rules;iocs=c.iocs;sigmaRules=c.sigmaRules;mapping=c.mapping;feedback=c.feedback;reviewPanel?.close();trainingPanel?.reset();baseFindings=bf;
 journal=[...c.journal,{time:new Date().toISOString(),action:'Opened saved case (original evidence not reverified)'}];aiRuns=[];
 aiAnswer=String(c.ai_output_unverified??'');$('answer').textContent=aiAnswer;$('caseName').value=String(c.name??'Untitled');$('caseNotes').value=String(c.notes??'');
 $('rulesInput').value=JSON.stringify(rules,null,2);$('tiInput').value=JSON.stringify(iocs,null,2);$('mapInput').value=JSON.stringify(mapping??{fields:{}},null,2);
 currentGraph={nodes:[],edges:[]};selected.clear();page=0;hourFilter=null;$('search').value='';refreshFindings();render();status('Case opened. Original file hashes were not reverified.');
}
$('loadCase').onclick=async()=>{if(busy)return;busy=true;try{const path=await open({multiple:false,filters:[{name:'DFIR case',extensions:['json']}]});if(path)await restoreCase(await invoke('load_case',{path}));}catch(e){status(String(e));}finally{busy=false;}};
$('newCase').onclick=()=>{if(busy||!confirm(t('Clear current workspace? Save first if needed.')))return;evidence=[];events=[];findings=[];baseFindings=[];rules=[];iocs=[];sigmaRules=[];mapping=null;feedback=[];reviewPanel?.close();trainingPanel?.reset();currentGraph={nodes:[],edges:[]};correlationResult={groups:[],findings:[]};hourFilter=null;page=0;$('search').value='';journal=[];aiAnswer='';aiRuns=[];selected.clear();$('caseName').value='Untitled investigation';$('caseNotes').value='';$('answer').textContent='';$('rulesInput').value='[]';render();};
$('htmlReport').onclick=async()=>{try{const path=await save({defaultPath:'dfir-report.html',filters:[{name:'HTML',extensions:['html']}]});if(path)await invoke('export_html',{path,html:htmlReport(caseData())});}catch(e){status(String(e));}};
$('cancelBatch').onclick=()=>{cancelled=true;};
$('batch').onclick=async()=>{if(busy||!events.length||!$('consent').checked)return status('Import records and authorize ALL records first.');if(!confirm(`Send all ${events.length} records to the configured AI endpoint?`))return;busy=true;cancelled=false;$('batch').disabled=true;$('ask').disabled=true;$('import').disabled=true;$('consent').checked=false;const endpoint=$('endpoint').value,model=$('model').value,key=$('key').value,question=$('question').value;let results=[];try{const askPrivate=privateGateway(backend,{endpoint,model,key});const chunks=batches(events);for(let i=0;i<chunks.length&&!cancelled;i++){status('AI batch {current}/{total}',{current:i+1,total:chunks.length});const started=performance.now();try{const answer=await askPrivate(question+feedbackContext(feedback,findings)+'\nReturn strict JSON: {"findings":[{"claim":"...","evidence":["exact ID"]}]}',chunks[i]);const validation=verifyAi(answer,chunks[i]);let jsonValid=false;try{JSON.parse(answer);jsonValid=true;}catch{}results.push({batch:i+1,evidence:chunks[i].map(e=>e.id),answer,validation});recordAiRun({mode:`batch ${i+1}/${chunks.length}`,model,host:aiHost(endpoint),events:chunks[i].length,ms:performance.now()-started,ok:true,validation,jsonValid});}catch(e){results.push({batch:i+1,error:String(e)});recordAiRun({mode:`batch ${i+1}/${chunks.length}`,model,host:aiHost(endpoint),events:chunks[i].length,ms:performance.now()-started,ok:false,error:String(e)});}aiAnswer=JSON.stringify(results,null,2);$('answer').textContent=aiAnswer;}status(`Batch stopped/completed: ${results.length}/${chunks.length} attempted. Verify results.`);journal.push({time:new Date().toISOString(),action:'AI batch',attempted:results.length,total:chunks.length});}catch(e){status(String(e));}finally{busy=false;$('batch').disabled=false;$('ask').disabled=false;$('import').disabled=false;renderExtra();if(!$('eval').hidden)renderEvalPanel();}};
render();
initTheme($('themeToggle'),()=>render());
addEventListener('resize',()=>{resizeCharts();const host=$('graphVisual');if(host?._cy)host._cy.resize();});

const advancedSection=el('article');advancedSection.innerHTML=`<h2>Advanced investigation</h2><p>Import MISP/STIX JSON or a TAXII collection export. Sigma JSON supports one named selection only.</p><label>Threat intelligence JSON<textarea id="tiInput"></textarea></label><button id="tiApply">Apply IOC data</button><label>Sigma rule JSON<textarea id="sigmaInput"></textarea></label><button id="sigmaApply">Add Sigma subset rule</button><label>Declarative parser mapping JSON<textarea id="mapInput" placeholder='{"fields":{"sender":"Account"}}'></textarea></label><button id="mapApply">Apply mapping to current records</button><button id="traceShow">Show message traces</button><button id="vaultCheck">Verify evidence vault</button><button id="aiVerify">Check AI evidence references</button><pre id="advancedOutput"></pre>`;$('rules').append(advancedSection);
$('tiApply').onclick=()=>{try{iocs=iocsFrom(JSON.parse($('tiInput').value));refreshFindings();render();status('{count} IOC entries loaded',{count:iocs.length});}catch(e){status(String(e));}};
$('sigmaApply').onclick=()=>{try{const r=JSON.parse($('sigmaInput').value);sigmaSubset([],r);if(sigmaRules.length>=100)throw Error('Maximum 100 Sigma rules');if(sigmaRules.some(x=>(x.id??x.title)===(r.id??r.title)))throw Error('Duplicate Sigma rule ID');sigmaRules.push(r);refreshFindings();render();status('Sigma subset rule added.');}catch(e){status(String(e));}};
$('mapApply').onclick=async()=>{if(busy)return;busy=true;try{const p=JSON.parse($('mapInput').value);parsePlugin({data:{}},p);const mapped=events.map(e=>parsePlugin(e,p));const bf=await invoke('analyze',{events:mapped});mapping=p;events=mapped;baseFindings=bf;const m=new Map(events.map(e=>[e.id,e]));for(const f of evidence)f.events=f.events.map(e=>m.get(e.id));refreshFindings();render();status('Mapping applied; original bytes unchanged.');}catch(e){status(String(e));}finally{busy=false;}};
$('traceShow').onclick=()=>{$('traceOutput').textContent=JSON.stringify(trace(events).slice(0,100).map(t=>({id:t.id,records:t.records.map(e=>({id:e.id,source:e.source,time:e.timestamp,action:e.action}))})),null,2);};
$('vaultCheck').onclick=async()=>{try{$('vaultOutput').textContent=JSON.stringify(await invoke('verify_vault'),null,2);}catch(e){status(String(e));}};
$('aiVerify').onclick=()=>{$('referenceOutput').textContent=JSON.stringify((()=>{try{const a=JSON.parse(aiAnswer);if(Array.isArray(a))return a.map(b=>({batch:b.batch,validation:b.validation??{error:b.error}}));}catch{}return verifyAi(aiAnswer,events);})(),null,2);};
const loadDb=el('button','Open SQLite case by name');$('case').append(loadDb);loadDb.onclick=async()=>{if(busy)return;busy=true;try{await restoreCase(await invoke('get_case',{id:$('caseName').value}));}catch(e){status(String(e));}finally{busy=false;}};

// RC3: bounded two-stage investigation, privacy-minimized context, graph and draft export.
const rc3=el('article');rc3.innerHTML=`<h2>Advanced investigation tools</h2><p>Evidence minimization is mandatory. Questions and notes are not automatically anonymized.</p><label>Local reference notes (JSON array of {id,text})<textarea id="kbRC3">[]</textarea></label><button id="agentsRC3">Run triage + independent review</button><button id="graphRC3">Export relationship graph</button><button id="ocsfRC3">Export OCSF draft</button><pre id="outRC3"></pre>`;$('ai').append(rc3);
$('agentsRC3').onclick=async()=>{if(busy||!events.length||!$('consent').checked)return status('Import evidence and authorize AI transfer first.');if(!confirm('Run two AI stages on all records? Reference notes and question are sent as entered. Evidence is minimized.'))return;busy=true;cancelled=false;$('consent').checked=false;const endpoint=$('endpoint').value,model=$('model').value,key=$('key').value;const started=performance.now();try{const docs=JSON.parse($('kbRC3').value);if(!Array.isArray(docs)||docs.length>100||docs.some(d=>typeof d.id!=='string'||typeof d.text!=='string'))throw Error('Invalid reference notes');const result=await investigate({events:[...events],question:$('question').value+feedbackContext(feedback,findings),docs,mask:true,stopped:()=>cancelled,verify:verifyAi,ask:(question,events)=>backend('ask_ai',{endpoint,model,key,question:localizedQuestion(question),events})});aiAnswer=JSON.stringify(result,null,2);$('answer').textContent=aiAnswer;let accepted=0,rejected=0;for(const row of result.results??[]){for(const v of [row.first,row.review]){accepted+=v?.accepted?.length??0;rejected+=v?.rejected?.length??0;}}recordAiRun({mode:'two-stage investigation',model,host:aiHost(endpoint),events:events.length,ms:performance.now()-started,ok:true,validation:{accepted:Array.from({length:accepted}),rejected:Array.from({length:rejected})}});status('Investigation completed or stopped; review claims and errors.');}catch(e){recordAiRun({mode:'two-stage investigation',model,host:aiHost(endpoint),events:events.length,ms:performance.now()-started,ok:false,error:String(e)});status(String(e));}finally{busy=false;}};
$('graphRC3').onclick=async()=>{try{const path=await save({defaultPath:'relationships.json'});if(path)await invoke('export_report',{path,report:graph(events)});}catch(e){status(String(e));}};
$('ocsfRC3').onclick=async()=>{try{const records=events.map(ocsfDraft).filter(Boolean);const path=await save({defaultPath:'ocsf-draft.json'});if(path)await invoke('export_report',{path,report:{status:'unvalidated draft',omitted:events.length-records.length,records}});}catch(e){status(String(e));}};

const graphPanel=el('article');graphPanel.innerHTML='<h2>Relationship graph</h2><p>Local graph, maximum 2,000 events. Select an entity to inspect its direct evidence links. Entity colors: events, senders, IPs and message IDs.</p><div class="graph-legend"><span><i style="background:#26f5d2"></i>Evidence event</span><span><i style="background:#f5e642"></i>Sender / recipient</span><span><i style="background:#b56cff"></i>IP address</span><span><i style="background:#68baff"></i>Message ID</span></div><button id="graphRefresh">Build graph</button> <input id="graphSearch" placeholder="Filter entity labels"><select id="graphNode"></select><div id="graphVisual" role="img" aria-label="Interactive relationship graph"></div><div id="graphLinks"></div>';$('graph').append(graphPanel);
let currentGraph={nodes:[],edges:[]};
function fillGraphNodes(){const q=$('graphSearch').value.toLowerCase();const select=$('graphNode');select.replaceChildren();for(const n of currentGraph.nodes.filter(n=>n.label.toLowerCase().includes(q)).slice(0,500)){const opt=el('option',n.type+': '+n.label);opt.value=n.id;select.append(opt);}showGraphLinks();}
function showGraphLinks(){const out=$('graphLinks');out.replaceChildren();const id=$('graphNode').value;const g=graphNeighborhood(currentGraph,id);drawNeighborhood(g,id);out.append(el('p',`${g.edges.length} direct links; ${currentGraph.truncated?'source graph truncated':'source graph within limit'}`));for(const edge of g.edges.slice(0,500)){const other=edge.source===id?edge.target:edge.source;const node=currentGraph.nodes.find(n=>n.id===other);const b=el('button',edge.relation+' → '+(node?.label??other));b.onclick=()=>{const event=events.find(e=>e.id===other);if(event){tab('explorer');$('detail').textContent=JSON.stringify(event,null,2);}else{$('graphSearch').value='';fillGraphNodes();const option=Array.from($('graphNode').options).find(o=>o.value===other);if(option){$('graphNode').value=other;showGraphLinks();}}};out.append(b,el('br'));}}
$('graphRefresh').onclick=()=>{currentGraph=graph(events);fillGraphNodes();};$('graphSearch').oninput=fillGraphNodes;$('graphNode').onchange=showGraphLinks;

function drawNeighborhood(g,id){const host=$('graphVisual');if(!host)return;renderGraph(host,g,{selected:id,onNode:nodeId=>{const option=Array.from($('graphNode').options).find(o=>o.value===nodeId);if(option){$('graphNode').value=nodeId;showGraphLinks();}else{const event=events.find(e=>e.id===nodeId);if(event){tab('explorer');$('detail').textContent=JSON.stringify(event,null,2);}}}});}
for(const id of ['endpoint','model','key','question','kbRC3'])$(id).addEventListener('input',()=>{$('consent').checked=false;});
$('preset').addEventListener('change',()=>{$('consent').checked=false;});

const pdfButton=el('button','Export PDF (local Python + ReportLab)');$('case').append(pdfButton);pdfButton.onclick=async()=>{if(busy)return;try{const path=await save({defaultPath:'dfir-report.pdf',filters:[{name:'PDF report',extensions:['pdf']}]});if(!path)return;const report=caseData();report.findings=report.findings.map(f=>({...f,description_original:f.description,description:t(f.description),severity:t(f.severity)}));report.evidence=report.evidence.map(({source,sha256,bytes})=>({source,sha256,bytes}));delete report.rules;delete report.iocs;delete report.sigmaRules;delete report.journal;busy=true;await invoke('export_pdf',{path,report});status('Local PDF exported. Analyst review required.');}catch(e){status(String(e));}finally{busy=false;}};


// NIGHTWIRE dev-only UI verification hook. Vite removes this block from production builds.
if(import.meta.env.DEV){
  const mk=(i,h,m,sender,recipient,ip,mid,action,data={})=>({id:`evt-${i}`,record:i,source:'synthetic-ui-sample.csv',timestamp:`2026-11-25T${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:00Z`,sender,recipient,ip,message_id:mid,action,data});
  window.__maildfirDev={
    loadSample(){
      const sample=[
        mk(1,8,5,'alice@example.test','bob@example.test','192.0.2.10','m-1','send'),
        mk(2,8,17,'alice@example.test','carol@example.test','192.0.2.10','m-2','send'),
        mk(3,8,44,'spoof@evil.test','bob@example.test','192.0.2.66','m-3','deliver',{raw:'https://bad.example/login'}),
        mk(4,9,2,'bob@example.test','dave@example.test','198.51.100.7','m-4','receive'),
        mk(5,9,18,'unknown@example.test','bob@example.test','203.0.113.9','m-5','login'),
        mk(6,9,31,'bob@example.test','eve@example.test','198.51.100.7','m-6','send'),
        mk(7,10,4,'admin@example.test','admin@example.test','192.0.2.20','m-7','new-inboxrule'),
        mk(8,10,22,'alice@example.test','external@partner.test','192.0.2.10','m-8','send'),
        mk(9,10,51,'bob@example.test','external@partner.test','198.51.100.7','m-9','send'),
        mk(10,11,7,'carol@example.test','bob@example.test','192.0.2.30','m-10','receive'),
        mk(11,11,19,'carol@example.test','bob@example.test','203.0.113.44','m-11','login'),
        mk(12,11,38,'dave@example.test','alice@example.test','198.51.100.8','m-12','send'),
        mk(13,12,3,'spoof@evil.test','alice@example.test','192.0.2.66','m-13','deliver',{raw:'https://bad.example/payload'}),
        mk(14,12,21,'eve@example.test','bob@example.test','203.0.113.9','m-14','receive'),
        mk(15,12,47,'bob@example.test','external@partner.test','198.51.100.7','m-15','send'),
        mk(16,13,5,'admin@example.test','admin@example.test','192.0.2.20','m-16','bulk-export'),
        mk(17,13,18,'alice@example.test','forward@external.test','192.0.2.10','m-17','forward-to'),
        mk(18,13,33,'carol@example.test','bob@example.test','192.0.2.30','m-18','receive'),
        mk(19,13,49,'unknown@example.test','bob@example.test','203.0.113.9','m-19','login'),
        mk(20,14,2,'dave@example.test','alice@example.test','198.51.100.8','m-20','send')
      ];
      evidence=[{source:'synthetic-ui-sample.csv',sha256:'0'.repeat(64),bytes:4096,events:sample,warnings:['Synthetic UI verification data; not evidence.']}];
      events=sample;
      baseFindings=[
        {rule:'MAIL-019',severity:'high',description:'phishing attempt (synthetic UI sample)',evidence:['evt-3']},
        {rule:'MAIL-007',severity:'high',description:'brute force (synthetic UI sample)',evidence:['evt-5']},
        {rule:'MAIL-002',severity:'medium',description:'new-inboxrule (synthetic UI sample)',evidence:['evt-7']},
        {rule:'MAIL-009',severity:'high',description:'high outbound (synthetic UI sample)',evidence:['evt-9']},
        {rule:'MAIL-017',severity:'medium',description:'impossible travel (synthetic UI sample)',evidence:['evt-11']},
        {rule:'MAIL-014',severity:'low',description:'spoof (synthetic UI sample)',evidence:['evt-13']},
        {rule:'MAIL-020',severity:'medium',description:'malicious ip (synthetic UI sample)',evidence:['evt-15']},
        {rule:'MAIL-004',severity:'medium',description:'forward-to (synthetic UI sample)',evidence:['evt-17']},
        {rule:'MAIL-001',severity:'low',description:'spf=fail (synthetic UI sample)',evidence:['evt-19']},
        {rule:'MAIL-015',severity:'high',description:'bulk export (synthetic UI sample)',evidence:['evt-16']}
      ];
      iocs=[
        {type:'ipv4-addr',value:'192.0.2.66',id:'misp-ip-1'},
        {type:'domain-name',value:'evil.test',id:'misp-domain-1'},
        {type:'url',value:'https://bad.example/login',id:'misp-url-1'},
        {type:'domain-name',value:'partner.test',id:'misp-domain-2'}
      ];
      aiRuns=[];
      selected.clear();
      journal=[{time:new Date().toISOString(),action:'Synthetic UI verification sample loaded'}];
      refreshFindings();
      render();
      tab('dashboard');
      status('Synthetic UI verification data loaded. Not evidence.');
    },
    loadAiSample(){
      const now=new Date().toISOString();
      aiRuns=[
        {time:now,mode:'selected evidence',model:'synthetic-ui-model',host:'localhost',events:5,ms:128,ok:true,jsonValid:true,validation:{accepted:[{},{},{}],rejected:[{}]}},
        {time:now,mode:'batch 1/2',model:'synthetic-ui-model',host:'localhost',events:10,ms:244,ok:true,jsonValid:true,validation:{accepted:[{},{}],rejected:[]}},
        {time:now,mode:'batch 2/2',model:'synthetic-ui-model',host:'localhost',events:10,ms:311,ok:false,error:'synthetic timeout'}
      ];
      tab('eval');
      renderEvalPanel();
      status('Synthetic AI evaluation sample loaded. Not a real model result.');
    }
  };
  // Browser-preview bridge. It never performs inference and is removed from production builds.
  const baseMock=async(name,args={})=>{
    const tools=[
      {name:'list_events',description:'Synthetic preview tool. The real backend lists case records.',parameters:{type:'object',properties:{limit:{type:'integer'}}},read_only:true,sensitive:false},
      {name:'event_stats',description:'Synthetic preview tool. The real backend summarizes the case snapshot.',parameters:{type:'object',properties:{}},read_only:true,sensitive:false},
      {name:'draft_report',description:'Synthetic preview tool. The real backend requires analyst approval.',parameters:{type:'object',properties:{title:{type:'string'}}},read_only:true,sensitive:true}
    ];
    if(name==='agent_tools')return tools;
    if(name==='agent_sessions')return [];
    if(name==='embedded_hardware')return {os:'preview',arch:'x86_64',logical_cores:8,total_ram_mb:16384,accelerators:['CPU'],recommended_threads:6,recommended_context:4096,recommended_gpu_layers:0,notes:['Synthetic browser-preview values. Not a real hardware probe.']};
    if(name==='embedded_engine_info')return {resource_dir:'(browser preview)',app_data_dir:'(browser preview)',expected_resource_binary:'engine/llama-server.exe',expected_user_binary:'(app data)/engine/llama-server.exe',binary_found:false,binary_path:null,version:null,notes:['The browser preview cannot inspect the filesystem or start a process.']};
    if(name==='embedded_models')return [];
    if(name==='embedded_status')return {running:false,ready:false,endpoint:null,model:null,port:null,started_at:null,detail:'Browser preview: no managed engine.'};
    if(name==='provider_test')return {ok:false,status:0,latencyMs:0,models:[],modelListed:false,detail:'Browser preview does not make provider requests.'};
    if(name==='ask_ai')return 'SYNTHETIC PREVIEW ONLY. The browser preview has no model, so this text is not an analysis. Run the Tauri application with a configured provider to exercise the real gateway.';
    if(name==='hf_search')return {items:[{id:'synthetic/gguf-preview',downloads:0,likes:0}]};
    if(name==='hf_files')return {repo:args.repo,files:[]};
    if(name==='workflow_list')return [];
    if(name==='workflow_validate')return {ok:true,order:(args.workflow?.nodes??[]).map(n=>n.id),errors:[]};
    if(name==='workflow_run')return {run_id:'synthetic-preview',status:'complete',steps:[],results:{},pending_node:null,error:null,duration_ms:4};
    if(name==='agent_run'){
      const request=args.request??{};
      return {
        session_id:request.session_id??'synthetic-preview',
        status:'complete',
        answer:'SYNTHETIC PREVIEW ONLY. The browser preview has no model and no Rust backend, so this text is not an analysis. Run the Tauri application with a configured provider to exercise the real bounded agent.',
        trace:[{step:1,kind:'tool',name:'event_stats',status:'ok',arguments:{},result:{events:request.events?.length??0},detail:'synthetic preview',ms:0}],
        iterations:1,
        tool_calls:1,
        tokens_estimated:0,
        minimized:false,
        model:'synthetic-preview',
        endpoint_host:'localhost',
        events:request.events?.length??0,
        findings:request.findings?.length??0,
        duration_ms:0,
        error:null
      };
    }
    throw new Error(`The browser preview has no handler for ${name}.`);
  };
  window.__maildfirMock=baseMock;
  import('./dev-preview.js').then(m=>{window.__maildfirMock=m.extendMock(baseMock);});
}

copilot=mountCopilot({
  status,
  tab,
  inspect:id=>{const e=events.find(x=>x.id===id);if(e){tab('explorer');$('detail').textContent=JSON.stringify(e,null,2);}},
  getCase:()=>({events,findings,iocs}),
  feedbackContext:()=>feedbackContext(feedback,findings),
  onAssessment:outcome=>{aiAnswer=String(outcome.answer??'');$('answer').textContent=aiAnswer;journal.push({time:new Date().toISOString(),action:'HELM assessment',model:outcome.model,status:outcome.status});renderExtra();}
});

// BEACON is the only floating assistant. The HELM agent studio above remains
// a normal workspace tab and does not mount a second floating panel.
mountBeacon({
  status,
  counts:()=>({events:events.length,findings:findings.length,evidence:evidence.length}),
  selected:()=>events.filter(e=>selected.has(e.id)),
  config:()=>{
    // Prefer the HELM studio provider when it has an endpoint; otherwise use
    // the app-wide AI settings. API keys stay in memory for this session.
    const helmEndpoint=document.getElementById('cpEndpoint');
    const helmModel=document.getElementById('cpModel');
    const helmKey=document.getElementById('cpKey');
    if(helmEndpoint?.value.trim()&&helmModel?.value.trim())return {endpoint:helmEndpoint.value.trim(),model:helmModel.value.trim(),key:helmKey?.value??''};
    return {endpoint:$('endpoint').value.trim(),model:$('model').value.trim(),key:$('key').value};
  },
  ask:(config,question,records)=>privateGateway(backend,config)(question+feedbackContext(feedback,findings),records),
  navigate:id=>tab(id),
  agent:async (config,question)=>{
    if(!events.length)throw Error('Import evidence before running HELM.');
    const outcome=await backend('agent_run',{
      request:{
        session_id:`beacon-${Date.now().toString(36)}`,
        task:localizedQuestion(question+feedbackContext(feedback,findings)),
        provider:config,
        events,
        findings,
        iocs,
        allowed_tools:[],
        approvals:[],
        max_iterations:8,
        token_budget:12000
      }
    });
    const answer=outcome.answer?.trim()||`HELM status: ${outcome.status}${outcome.error?` - ${outcome.error}`:''}`;
    return `${answer}\n\nHELM ${outcome.status} · ${outcome.iterations} iteration(s) · ${outcome.tool_calls} tool call(s) · ${outcome.model}`;
  }
});

// A single, visible investigation path links the existing specialist workspaces.
const workflow=el('div',undefined,'workflow-steps');
for(const [label,target] of [['1 · Preserve evidence','evidence'],['2 · Review records','explorer'],['3 · Triage findings','findings'],['4 · Report','case']]){const button=el('button',label);button.onclick=()=>tab(target);workflow.append(button);}
$('dashboard').prepend(workflow);
const quality=el('div');quality.id='quality';workflow.after(quality);
function renderQuality(){const out=$('quality');if(!out)return;out.replaceChildren();if(!events.length)return;const q=timeQuality(events);for(const [key,count] of [['Missing timestamps: {count}',q.missing],['Ambiguous timestamps: {count}',q.ambiguous]])out.append(el('span',t(key,{count})));}
const filter=el('select');filter.id='severityFilter';filter.setAttribute('aria-label','Priority / Priorität / Öncelik');
for(const value of ['', 'high','medium','low','info']){const option=el('option',value||'All priorities');option.value=value;filter.append(option);}
filter.onchange=()=>listFindings('findinglist',findings);$('findinglist').before(filter);
const logPanel=el('article');logPanel.append(el('h2','Application messages'));const log=el('ol');log.id='operationLog';logPanel.append(log);$('case').append(logPanel);
const note=el('p','Raw evidence is preserved. AI explanations require analyst verification.');$('explorer').prepend(note);
mountLocale(document.body,()=>{renderCyber();renderAnalysisPanels();renderRows();updateSelection();listFindings('recent',findings.slice(0,8));listFindings('findinglist',findings);renderQuality();renderOperations();$('status').textContent=t(...lastStatus);$('consent').checked=false;if($('cpConsent')){$('cpConsent').checked=false;$('cpConsent').dispatchEvent(new Event('change'));}rulesWorkbench?.render();reviewPanel?.render();trainingPanel?.render();});
renderQuality();

for(const [buttonId,target,outputId] of [['vaultCheck','evidence','vaultOutput'],['traceShow','timeline','traceOutput'],['aiVerify','ai','referenceOutput']]){
 const panel=el('article');panel.append($(buttonId));const output=el('pre');output.id=outputId;panel.append(output);$(target).append(panel);
}
const intelTools=el('article');intelTools.append($('tiInput').closest('label'),$('tiApply'));$('ti').prepend(intelTools);

const resetFilters=el('button','Clear filters');resetFilters.onclick=()=>{hourFilter=null;$('search').value='';page=0;renderRows();};$('explorer').querySelector('.toolbar').append(resetFilters);

function prepareSmart(task=smartTask()){tab('copilot');document.querySelector('[data-cp-tab="assistant"]')?.click();$('cpTask').value=task;$('cpConsent').checked=false;$('cpConsent').dispatchEvent(new Event('change'));$('cpTask').focus();}
rulesWorkbench=mountRulesWorkbench({host:$('rules'),events:()=>events,editors:{custom:$('rulesInput'),sigma:$('sigmaInput'),mapping:$('mapInput')},status,prepareSmart});
reviewPanel=mountReviewPanel({host:$('findings'),getState:()=>({feedback,findings,events}),save:next=>{feedback=next;journal.push({time:new Date().toISOString(),action:'Analyst review',reviewed:next.length});listFindings('findinglist',findings);listFindings('recent',findings.slice(0,8));renderExtra();},status});
const smartButton=el('button','Prepare smart log analysis','primary');smartButton.id='smartLogAnalysis';smartButton.onclick=()=>prepareSmart();$('ai').prepend(smartButton);

trainingPanel=mountTraining({host:$('settings'),getState:()=>({events,findings,feedback}),status,saveFile:async jsonl=>{const path=await save({defaultPath:'mailsonar-reviewed-training.jsonl',filters:[{name:'JSONL training dataset',extensions:['jsonl']}]});if(!path)return false;await invoke('export_html',{path,html:jsonl});return true;}});


// ---------------------------------------------------------------------------
// Simplified shell: Start page, e-mail forensics view, one AI connection,
// one-click AI analysis, AI rule writing and the Hugging Face model hub.
// ---------------------------------------------------------------------------
{
 const main=document.querySelector('main');
 for(const [id,before] of [['home','dashboard'],['training','dashboard'],['email','findings'],['investigations','settings']]){const s=el('section',undefined,'tab');s.id=id;s.hidden=true;main.insertBefore(s,$(before));}
 const nav=organizeNav(document.querySelector('aside nav'),id=>tab(id));
 const go=id=>{nav.reveal(id);tab(id);};
 const api={
  backend,status,tab:go,
  getCase:()=>({events,findings,iocs,evidence}),
  getRules:()=>rules,
  selectedIds:()=>[...selected],
  select:ids=>{selected.clear();for(const id of [...new Set(ids)].slice(0,25))selected.add(id);renderRows();updateSelection();},
  lookup:(kind,value)=>backend('open_lookup',{kind,value}),
  pickFiles:async()=>{const p=await open({multiple:true,filters:[{name:'Evidence files',extensions:['csv','json','jsonl','ndjson','xml','txt','log','eml','mbox','mbx','msg','evtx','zip','gz','gzip','xlsx']}]});return p?(Array.isArray(p)?p:[p]):[];},
  importSubset:(rows,name)=>{if(events.length+rows.length>100000)return status('Workspace limit is 100,000 records; copy fewer records.');const known=new Set(events.map(e=>e.id));const fresh=rows.filter(e=>!known.has(e.id)).map(normalize);evidence.push({source:name,sha256:'0'.repeat(64),bytes:0,events:fresh,warnings:['Subset copied from a large investigation; original file hashes are in that investigation.'],profile:{}});events.push(...fresh);backend('analyze',{events}).then(bf=>{baseFindings=bf;refreshFindings();render();status('{count} records copied into the workspace.',{count:fresh.length});go('dashboard');});},
  searchExplorer:text=>{go('explorer');hourFilter=null;$('search').value=text;page=0;renderRows();},
  feedbackContext:()=>feedbackContext(feedback,findings),
  inspect:id=>{const e=events.find(x=>x.id===id);if(e){go('explorer');$('detail').textContent=JSON.stringify(e,null,2);}else status('Evidence ID not found in the current case.');},
  addRules:list=>{const merged=[...rules.filter(r=>!list.some(n=>n.id===r.id)),...list];rules=validateRules(merged);$('rulesInput').value=JSON.stringify(rules,null,2);journal.push({time:new Date().toISOString(),action:'Rules added',ids:list.map(r=>r.id)});refreshFindings();render();return list.length;},
  importFiles:()=>$('import').click(),
  loadSample:async(id='bec-demo')=>{if(busy)return;busy=true;try{status('Loading the synthetic sample case…');const sample=await backend('sample_materialize',{id});await importPaths(sample.paths,'Sample case loaded (synthetic)');const known=new Set(iocs.map(i=>i.type+'|'+i.value));iocs=[...iocs,...sample.iocs.filter(i=>!known.has(i.type+'|'+i.value))];$('tiInput').value=JSON.stringify(iocs,null,2);if($('caseName').value==='Untitled investigation')$('caseName').value='Demo: BEC kill chain (synthetic)';refreshFindings();render();status('Sample case loaded: {count} records. Synthetic data, not evidence.',{count:events.length});}catch(e){status(String(e));}finally{busy=false;}},
  loadDataset:async id=>{resetWorkspace();render();await api.loadSample(id);},
  ask:(task,title)=>{go('ai');quick.run(task,null,title);},
  quickRun:skill=>{const p=PROFILES.find(x=>x.skill===skill)??PROFILES[0];go('ai');quick.run(p.task,p.skill,t(p.title));},
  startModel:path=>{go('settings');hub.startModel(path);},
  onAiResult:(outcome,title)=>{aiAnswer=String(outcome.answer??'');$('answer').textContent=aiAnswer;journal.push({time:new Date().toISOString(),action:'HELM analysis',title,model:outcome.model,status:outcome.status});recordAiRun({mode:`helm ${outcome.skill??''}`.trim(),model:outcome.model,host:outcome.endpoint_host,events:outcome.events,ms:outcome.duration_ms,ok:outcome.status==='complete'});}
 };
 const resetWorkspace=()=>{evidence=[];events=[];findings=[];baseFindings=[];rules=[];iocs=[];sigmaRules=[];mapping=null;feedback=[];reviewPanel?.close();trainingPanel?.reset();currentGraph={nodes:[],edges:[]};correlationResult={groups:[],findings:[]};hourFilter=null;page=0;$('search').value='';journal=[];aiAnswer='';aiRuns=[];selected.clear();$('caseName').value='Untitled investigation';$('caseNotes').value='';$('answer').textContent='';$('rulesInput').value='[]';};
 const home=mountHome({section:$('home'),api});
 mountAcademy({section:$('training'),api});
 mountLargeCases({section:$('investigations'),api});
 const email=mountEmailView({section:$('email'),api});
 // AI analysis: one-click profiles first, the original manual tools folded below.
 const deep=foldAdvanced($('ai'),'Deep analysis of selected records (advanced)');
 const quick=mountQuickAi({host:$('ai'),api});
 mountAdvancedAi({details:deep,api});
 const graphView=mountGraphFilters({section:$('graph'),api});
 extraRenderers.push(()=>{if(!$('graph').hidden)graphView.draw();});
 // Rules: AI writer first, guide and JSON/Sigma/mapping editors folded below.
 foldAdvanced($('rules'),'Advanced: rule guide, JSON / Sigma editors and field mapping');
 mountRuleAi({host:$('rules'),api});
 // AI model page replaces the separate AI settings form (kept in sync, folded).
 foldAdvanced($('settings'),'Advanced: raw endpoint fields and fine-tuning export');
 const hub=mountModelHub({section:$('settings'),api});
 bindLegacyFields();
 extraRenderers.push(()=>home.render(),()=>email.render());
 document.querySelector('nav button[data-tab="settings"]')?.addEventListener('click',()=>hub.refresh());
 window.__mailsonarApi=import.meta.env.DEV?api:undefined;
 render();
 go(events.length?'dashboard':'home');
}
