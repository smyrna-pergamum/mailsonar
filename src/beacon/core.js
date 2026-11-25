// BEACON offline guide and consent-checked request builders.
// The host still owns minimization, authorization and the backend gateway.

export const topics = [
  ['import', 'How do I import email logs?', 'Open Import evidence and select files. CSV, JSON, JSONL, XML, TXT, LOG, EML, MSG, EVTX, ZIP, GZIP and XLSX have parser support of varying depth. Review import warnings and verify evidence before drawing conclusions.', /import|upload|dosya|y[uü]kle|datei|hochladen/iu, 'explorer'],
  ['models', 'How do I configure AI?', 'Open AI settings. Select a local llama.cpp endpoint or an approved OpenAI-compatible endpoint and enter its exact model identifier. The local engine requires a compatible llama-server binary and GGUF model. Core analysis works without AI.', /model|gguf|llama|openai|api|ki einstellen/iu, 'settings'],
  ['findings', 'What do the findings mean?', 'Findings are investigative indicators, not confirmed incidents. Review the supporting source record and consider benign explanations before confirming a finding.', /finding|risk|severity|bulgu|befund/iu, 'findings'],
  ['graph', 'How do I inspect related events?', 'Open Timeline & correlation. Inspect shared identifiers and the relationship graph if available. Shared IDs and time proximity alone do not prove causality.', /graph|timeline|trace|correl|harita|zeitlinie/iu, 'timeline'],
  ['evidence', 'How do I verify evidence?', 'Open Evidence or Case management and use the vault verification control if available. SHA-256 checks verify stored bytes against a recorded hash; they do not prove authenticity or an immutable chain of custody.', /evidence|hash|vault|delil|beweis/iu, 'evidence'],
  ['agent', 'How do I use HELM and WAYPOINT?', 'HELM is the bounded DFIR agent. Open Agent studio to run read-only case tools with an explicit provider authorization. WAYPOINT is the workflow studio: validate a DAG, review every node and approve execution. BEACON itself never executes tools or changes evidence.', /agent|helm|workflow|waypoint|flow|ajan/iu, 'copilot']
];

function checkedQuestion(question) {
  const text = String(question ?? '').trim();
  if (!text || text.length > 2000) throw Error('Enter a question of 1-2000 characters.');
  return text;
}

function endpointUrl(config) {
  let url;
  try {
    url = new URL(String(config?.endpoint ?? ''));
  } catch {
    throw Error('Configure an AI endpoint first.');
  }
  const loopback = url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  if (url.username || url.password || !(url.protocol === 'https:' || loopback)) {
    throw Error('Use HTTPS or loopback HTTP without URL credentials.');
  }
  return url;
}

function checkedConfig(config) {
  const cfg = {...config};
  const url = endpointUrl(cfg);
  if (!String(cfg.model ?? '').trim()) throw Error('Configure an AI model first.');
  return {cfg, url};
}

export function localAnswer(question, counts = {}) {
  const q = checkedQuestion(question);
  if (/^(case summary|vaka [öo]zeti|fall[uü]bersicht)$/iu.test(q)) {
    return {text: `Current workspace: ${Number(counts.events) || 0} events, ${Number(counts.findings) || 0} findings, ${Number(counts.evidence) || 0} evidence files. Counts are not a determination of compromise.`};
  }
  const topic = topics.find((entry) => entry[3].test(q));
  return topic
    ? {text: topic[2], tab: topic[4]}
    : {text: 'No matching offline help topic. Try a suggested question or switch to Selected evidence AI for a case-specific question. Offline help is a keyword-based guide, not an LLM.'};
}

export async function askSelected({question, records, config, approve, ask}) {
  const text = checkedQuestion(question);
  if (!Array.isArray(records) || records.length < 1 || records.length > 25) {
    throw Error('Select 1-25 records in Log Explorer.');
  }
  const {cfg, url} = checkedConfig(config);
  const snapshot = structuredClone(records);
  const allowed = await approve({destination: url.origin, model: cfg.model, count: snapshot.length, question: text});
  if (!allowed) return null;
  return await ask(cfg, text, snapshot);
}

// Runs the bounded HELM agent. The Rust backend authorizes and executes every
// tool against the current case; this function only performs the UI consent
// checkpoint and forwards the task.
export async function askAgent({question, counts, config, approve, run}) {
  const text = checkedQuestion(question);
  if (!counts || !Number(counts.events)) throw Error('Import evidence before running HELM.');
  const {cfg, url} = checkedConfig(config);
  if (typeof run !== 'function') throw Error('HELM is unavailable in this host.');
  const allowed = await approve({destination: url.origin, model: cfg.model, events: Number(counts.events), question: text});
  if (!allowed) return null;
  return await run(cfg, text);
}
