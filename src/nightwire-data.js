// Pure, dependency-free data helpers for the NIGHTWIRE visual system.
// Everything here is derived from workspace data; no dashboard statistic is hardcoded.

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'benign', 'info', 'unknown'];

export const SEVERITY_COLORS = {
  critical: '#ff597d',
  high: '#ff9d52',
  medium: '#f5e642',
  low: '#68baff',
  benign: '#42dca1',
  info: '#a5b2c4',
  unknown: '#92a9bd'
};

export const ENTITY_COLORS = {
  event: '#26f5d2',
  sender: '#f5e642',
  ip: '#b56cff',
  message_id: '#68baff',
  recipient: '#42dca1'
};

export const ENTITY_LABELS = {
  event: 'Evidence event',
  sender: 'Sender / recipient',
  ip: 'IP address',
  message_id: 'Message ID',
  recipient: 'Recipient'
};

// Heuristic rule-to-technique mapping. Counts are observations, not coverage claims.
export const MITRE_TECHNIQUES = [
  { id: 'T1566', name: 'Phishing', tactic: 'Initial Access' },
  { id: 'T1656', name: 'Impersonation', tactic: 'Initial Access' },
  { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access' },
  { id: 'T1528', name: 'Steal Application Access Token', tactic: 'Credential Access' },
  { id: 'T1114', name: 'Email Collection', tactic: 'Collection' },
  { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion' },
  { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', tactic: 'Exfiltration' },
  { id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control' },
  { id: 'T1485', name: 'Data Destruction', tactic: 'Impact' }
];

export function severityKey(value) {
  const key = String(value ?? '').toLowerCase();
  return Object.hasOwn(SEVERITY_COLORS, key) ? key : 'unknown';
}

export function severityColor(value) {
  return SEVERITY_COLORS[severityKey(value)];
}

export function entityColor(value) {
  return ENTITY_COLORS[value] ?? ENTITY_COLORS.event;
}

export function median(values) {
  const sorted = values.filter(Number.isFinite).sort((a, b) => a - b);
  if (!sorted.length) return null;
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

export function hourlyBuckets(events, limit = 24) {
  const buckets = new Map();
  for (const event of Array.isArray(events) ? events : []) {
    const timestamp = Date.parse(event?.timestamp);
    if (!Number.isFinite(timestamp)) continue;
    const date = new Date(timestamp);
    date.setUTCMinutes(0, 0, 0);
    const key = `${date.toISOString().slice(0, 13)}:00Z`;
    buckets.set(key, (buckets.get(key) || 0) + 1);
  }
  const series = [...buckets].sort((a, b) => a[0].localeCompare(b[0]));
  return limit > 0 ? series.slice(-limit) : series;
}

export function severityCounts(findings) {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((key) => [key, 0]));
  for (const finding of Array.isArray(findings) ? findings : []) {
    counts[severityKey(finding?.severity)] += 1;
  }
  return SEVERITY_ORDER.map((severity) => ({
    severity,
    count: counts[severity],
    color: SEVERITY_COLORS[severity]
  }));
}

function parentTechnique(id) {
  return String(id).split('.')[0];
}

export function techniqueCounts(findings) {
  const counts = new Map();
  for (const finding of Array.isArray(findings) ? findings : []) {
    for (const technique of Array.isArray(finding?.attack) ? finding.attack : []) {
      const id = parentTechnique(technique);
      counts.set(id, (counts.get(id) || 0) + 1);
    }
  }
  return counts;
}

export function mitreRows(findings) {
  const counts = techniqueCounts(findings);
  const byTactic = new Map();
  for (const technique of MITRE_TECHNIQUES) {
    if (!byTactic.has(technique.tactic)) byTactic.set(technique.tactic, []);
    byTactic.get(technique.tactic).push({ ...technique, count: counts.get(technique.id) || 0 });
  }
  return [...byTactic].map(([tactic, techniques]) => ({ tactic, techniques }));
}

export function iocTypeCounts(iocs) {
  const counts = new Map();
  for (const ioc of Array.isArray(iocs) ? iocs : []) {
    const type = String(ioc?.type ?? 'unknown');
    counts.set(type, (counts.get(type) || 0) + 1);
  }
  return [...counts].map(([type, count]) => ({ type, count })).sort((a, b) => b.count - a.count || a.type.localeCompare(b.type));
}

export function parseIocMatch(finding) {
  if (finding?.rule !== 'TI-001' || typeof finding.description !== 'string') return null;
  const match = finding.description.match(/^IOC match \(([^)]+)\): (.*); source (.*)$/);
  if (!match) return null;
  return { type: match[1], value: match[2], source: match[3] };
}

export function matchedIndicators(findings) {
  const counts = new Map();
  for (const finding of Array.isArray(findings) ? findings : []) {
    const parsed = parseIocMatch(finding);
    if (!parsed) continue;
    const key = `${parsed.type}\u0000${parsed.value}\u0000${parsed.source}`;
    const current = counts.get(key);
    if (current) current.count += 1;
    else counts.set(key, { ...parsed, count: 1 });
  }
  return [...counts.values()].sort((a, b) => b.count - a.count || a.value.localeCompare(b.value));
}

export function aiEvaluationMetrics(runs) {
  const list = (Array.isArray(runs) ? runs : []).filter((run) => run && typeof run === 'object');
  const completed = list.filter((run) => run.ok === true).length;
  const failed = list.filter((run) => run.ok === false).length;
  const eventsSent = list.reduce((total, run) => total + (Number(run.events) || 0), 0);
  const latency = median(list.map((run) => Number(run.ms)));
  let accepted = 0;
  let rejected = 0;
  for (const run of list) {
    accepted += Number(run.validation?.accepted?.length ?? run.accepted ?? 0) || 0;
    rejected += Number(run.validation?.rejected?.length ?? run.rejected ?? 0) || 0;
  }
  const claims = accepted + rejected;
  const measuredJson = list.filter((run) => typeof run.jsonValid === 'boolean');
  const validJson = measuredJson.filter((run) => run.jsonValid).length;
  return {
    total: list.length,
    completed,
    failed,
    eventsSent,
    medianMs: latency,
    accepted,
    rejected,
    claims,
    referenceRate: claims ? accepted / claims : null,
    jsonMeasured: measuredJson.length,
    validJson,
    jsonRate: measuredJson.length ? validJson / measuredJson.length : null,
    models: [...new Set(list.map((run) => run.model).filter(Boolean))],
    modes: [...new Set(list.map((run) => run.mode).filter(Boolean))]
  };
}

export function formatPercent(value) {
  return Number.isFinite(value) ? `${(value * 100).toFixed(1)}%` : 'Not Evaluated';
}

export function formatDuration(value) {
  return Number.isFinite(value) ? `${Math.round(value)} ms` : 'Not Evaluated';
}
