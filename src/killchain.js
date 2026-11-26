import {eventTime} from './event-time.js';
// COR-004: deterministic e-mail kill-chain correlation per account.
// Phishing received -> sign-in anomaly -> mailbox manipulation -> fraud / exfiltration.
// Each stage must come from an existing finding on a record tied to the same account,
// and stages must occur in order within the window. A chain is a lead for the analyst,
// not proof: every stage still needs confirmation from its own log source.

export const STAGES = [
  {id: 'delivery', label: 'Phishing / malicious mail received', role: 'recipient', rules: ['MAIL-001', 'MAIL-011', 'MAIL-012', 'MAIL-013', 'MAIL-014', 'MAIL-019', 'MAIL-022', 'MAIL-023']},
  {id: 'access', label: 'Suspicious sign-in or MFA change', role: 'sender', rules: ['COR-001', 'MAIL-003', 'MAIL-007', 'MAIL-017', 'MAIL-029']},
  {id: 'manipulation', label: 'Mailbox rule, forwarding or deletion', role: 'sender', rules: ['MAIL-002', 'MAIL-004', 'MAIL-026', 'MAIL-027', 'MAIL-028']},
  {id: 'action', label: 'Fraudulent request or exfiltration', role: 'sender', rules: ['MAIL-021', 'MAIL-025', 'MAIL-009', 'MAIL-015', 'COR-002']}
];
const WINDOW_MS = 24 * 3600 * 1000;
const norm = value => String(value ?? '').trim().toLowerCase();

function stageHits(events, findings) {
  const byId = new Map(events.map(e => [e.id, e]));
  const hits = new Map(); // account -> stage -> [{t, id, rule}]
  for (const finding of findings) {
    for (const stage of STAGES) {
      if (!stage.rules.includes(finding.rule)) continue;
      for (const id of finding.evidence ?? []) {
        const event = byId.get(id);
        const account = norm(event?.[stage.role]);
        const t = eventTime(event?.timestamp);
        if (!account.includes('@') || !Number.isFinite(t)) continue;
        if (!hits.has(account)) hits.set(account, new Map());
        const perStage = hits.get(account);
        if (!perStage.has(stage.id)) perStage.set(stage.id, []);
        perStage.get(stage.id).push({t, id, rule: finding.rule});
      }
    }
  }
  return hits;
}

/** Earliest ordered chain: each stage is the first hit after the previous stage. */
function orderedChain(perStage) {
  const chain = [];
  let after = -Infinity;
  for (const stage of STAGES) {
    const candidates = (perStage.get(stage.id) ?? []).filter(h => h.t >= after).sort((a, b) => a.t - b.t);
    if (!candidates.length) continue;
    const hit = candidates[0];
    if (chain.length && hit.t - chain[0].t > WINDOW_MS) continue;
    chain.push({stage: stage.id, label: stage.label, time: new Date(hit.t).toISOString(), evidence: hit.id, rule: hit.rule, t: hit.t});
    after = hit.t;
  }
  return chain;
}

export function killChains(events, findings) {
  const out = [];
  for (const [account, perStage] of stageHits(events ?? [], findings ?? [])) {
    const chain = orderedChain(perStage);
    const stages = new Set(chain.map(c => c.stage));
    // Require the access stage plus at least two others; delivery alone is common noise.
    if (chain.length < 3 || !stages.has('access')) continue;
    const hours = ((chain.at(-1).t - chain[0].t) / 3600000).toFixed(1);
    out.push({
      rule: 'COR-004',
      severity: chain.length === 4 ? 'critical' : 'high',
      description: `Possible account-takeover / BEC chain for ${account}: ${chain.map(c => c.label).join(' → ')} (${chain.length}/4 stages in ${hours} h). Confirm each stage in its own log source.`,
      evidence: chain.map(c => c.evidence),
      account,
      chain: chain.map(({t, ...rest}) => rest)
    });
  }
  return out.sort((a, b) => b.chain.length - a.chain.length);
}
