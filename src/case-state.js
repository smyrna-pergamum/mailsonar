import {validateRules} from './analysis.js';
import {parsePlugin, sigmaSubset} from './advanced.js';
import {validateFeedback} from './feedback.js';

// Validate before changing any live state. JSON and SQLite share this boundary.
export function validateCase(c) {
  if (!c || c.schema !== 'mail-dfir/1.0' || !Array.isArray(c.evidence)) throw Error('Invalid case schema');
  const ids = new Set();
  let count = 0;
  for (const f of c.evidence) {
    if (!f || typeof f.sha256 !== 'string' || typeof f.source !== 'string' || !Array.isArray(f.events) || !Array.isArray(f.warnings)) throw Error('Invalid evidence manifest');
    for (const e of f.events) {
      if (!e || ['id','timestamp','sender','recipient','ip','message_id','action'].some(k => typeof e[k] !== 'string') || !e.id || ids.has(e.id)) throw Error('Invalid or duplicate evidence ID');
      ids.add(e.id);
      if (++count > 20000) throw Error('Case exceeds 20000 records');
    }
  }
  validateRules(c.rules ?? []);
  if (!Array.isArray(c.iocs ?? []) || (c.iocs ?? []).some(i => !i || typeof i.type !== 'string' || typeof i.value !== 'string')) throw Error('Invalid IOC data');
  if (!Array.isArray(c.sigmaRules ?? []) || (c.sigmaRules ?? []).length > 100) throw Error('Invalid Sigma rules');
  for (const r of c.sigmaRules ?? []) sigmaSubset([], r);
  if (c.mapping) parsePlugin({data:{}}, c.mapping);
  if (!Array.isArray(c.journal ?? [])) throw Error('Invalid journal');
  const feedback=validateFeedback(c.feedback??[],c.evidence.flatMap(f=>f.events));
  return {...c, rules:c.rules ?? [], iocs:c.iocs ?? [], sigmaRules:c.sigmaRules ?? [], mapping:c.mapping ?? null, journal:c.journal ?? [],feedback};
}

export function prioritizeFindings(items) {
  const unique = new Map();
  for (const f of items) {
    const evidence = [...new Set(f.evidence)].sort();
    const key = JSON.stringify([f.rule, f.description, evidence]);
    if (!unique.has(key)) unique.set(key, {...f, evidence});
  }
  const rank = {critical:0, high:1, medium:2, low:3, info:4};
  return [...unique.values()].sort((a,b) => (rank[a.severity] ?? 5) - (rank[b.severity] ?? 5));
}
