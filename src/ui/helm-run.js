// Shared HELM runner used by Quick AI, rule writing, e-mail analysis and the home page.
// The Rust backend owns tool execution, minimization and limits; this module only
// builds the request, asks for consent when data would leave the device and streams
// trace steps to the caller.
import {localizedQuestion, t} from '../i18n.js';
import {getProvider, hostOf, isLoopback, providerReady, tokenBudget as budgetFor} from './provider.js';

let listenFn = null;
async function listenSteps(handler) {
  if (!window.__TAURI_INTERNALS__) return () => {};
  if (!listenFn) listenFn = (await import('@tauri-apps/api/event')).listen;
  return listenFn('helm://step', event => handler(event.payload));
}

/** Remote providers need an explicit per-run confirmation; loopback stays on device. */
export function confirmTransfer(provider, confirmFn = globalThis.confirm) {
  if (isLoopback(provider.endpoint)) return true;
  return confirmFn(t('Send this task and minimized tool results to {host}? Identifiers are replaced by aliases and raw record data is removed.', {host: hostOf(provider.endpoint)}));
}

export function newSessionId(prefix = 'ui') {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
}

/**
 * Run the agent. `onStep` receives live trace steps. Returns the AgentOutcome.
 * Throws with a readable message when no provider or no evidence is available.
 */
export async function runHelm({backend, getCase, task, skill = null, history = [], sessionId = newSessionId(), onStep, maxIterations = 10, tokenBudget, feedback = '', investigation = null}) {
  const provider = getProvider();
  if (!providerReady(provider)) throw Error(t('Connect an AI model first (AI model page).'));
  const current = getCase();
  if (!investigation && !current.events?.length) throw Error(t('Import evidence or load the sample case first.'));
  if (!confirmTransfer(provider)) throw Error(t('Cancelled: nothing was sent.'));
  const unlisten = onStep ? await listenSteps(payload => {
    if (payload?.session_id === sessionId) onStep(payload.step);
  }) : () => {};
  try {
    return await backend('agent_run', {
      request: {
        session_id: sessionId,
        task: localizedQuestion(task + feedback),
        provider: {endpoint: provider.endpoint, model: provider.model, key: provider.key},
        events: investigation ? [] : current.events,
        findings: investigation ? [] : current.findings ?? [],
        iocs: current.iocs ?? [],
        investigation,
        allowed_tools: [],
        approvals: [],
        max_iterations: maxIterations,
        token_budget: tokenBudget ?? budgetFor(provider),
        skill,
        history
      }
    });
  } finally {
    unlisten();
  }
}

const RULE_FIELDS = ['sender', 'recipient', 'ip', 'action', 'message_id', 'source', 'timestamp'];

/** Extract MailSonar custom rules from an AI answer (last JSON array block wins). */
export function parseRules(answer) {
  const text = String(answer ?? '');
  const blocks = [...text.matchAll(/```(?:json)?\s*([\s\S]*?)```/g)].map(m => m[1]);
  const bare = text.match(/\[\s*\{[\s\S]*\}\s*\]/);
  if (bare) blocks.push(bare[0]);
  for (const block of blocks.reverse()) {
    try {
      let value = JSON.parse(block.trim());
      if (!Array.isArray(value)) value = [value];
      const rules = value.filter(r => r && typeof r === 'object').map((r, i) => ({
        id: String(r.id || `CUSTOM-AI-${String(i + 1).padStart(3, '0')}`).toUpperCase().replace(/[^A-Z0-9-]/g, '-').slice(0, 40),
        field: RULE_FIELDS.includes(r.field) ? r.field : 'action',
        contains: String(r.contains ?? '').trim().slice(0, 200),
        severity: ['low', 'medium', 'high'].includes(r.severity) ? r.severity : 'medium',
        description: String(r.description ?? 'AI-proposed rule; analyst review required.').slice(0, 300)
      })).filter(r => r.contains);
      if (rules.length) return rules.slice(0, 10);
    } catch {
      // Try the next candidate block.
    }
  }
  return [];
}

/** Human-readable label for a trace step. */
export function stepLabel(step) {
  if (step.kind === 'model') return `◆ ${step.name} · ${step.status === 'running' ? `${step.detail} …` : `${(step.ms / 1000).toFixed(1)} s`}`;
  const args = step.arguments && Object.keys(step.arguments).length ? ` ${JSON.stringify(step.arguments).slice(0, 80)}` : '';
  return `${step.kind === 'preload' ? '⤓' : '⚙'} ${step.name}${args} · ${step.status}`;
}
