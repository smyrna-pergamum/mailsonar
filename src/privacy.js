import {localizedQuestion} from './i18n.js';
import {minimized} from './investigation.js';
// One session map for all requests in an investigation. Raw content is never sent.
export function privateGateway(invoke, config){
 const aliases=new Map();
 return async (question,events)=>{
  if(typeof question!=='string'||question.length>16000)throw Error('Question must be at most 16000 characters');
  if(!Array.isArray(events)||events.length<1||events.length>25)throw Error('Expected 1–25 events');
  return invoke('ask_ai',{...config,question:localizedQuestion(question),events:events.map(e=>minimized(e,aliases))});
 };
}
export function graphNeighborhood(g,id){
 const edges=g.edges.filter(e=>e.source===id||e.target===id);
 const ids=new Set([id,...edges.flatMap(e=>[e.source,e.target])]);
 return {nodes:g.nodes.filter(n=>ids.has(n.id)),edges};
}
