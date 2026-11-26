// One AI provider for the whole app (AI analysis, HELM, BEACON, rule writing).
// Endpoint, preset and model persist locally; API keys and the per-run engine key
// stay in memory only. Legacy form fields are kept in sync so older panels keep working.
import {PROVIDER_PRESETS, providerPreset} from '../assistant-data.js';
import {t} from '../i18n.js';

const KEY = 'maildfir.copilot.provider';
const LAST_MODEL = 'mailsonar.lastModel';
const listeners = new Set();
let state = load();

function load() {
  try {
    const saved = JSON.parse(localStorage.getItem(KEY) ?? '{}');
    const preset = providerPreset(saved.preset ?? 'embedded');
    return {preset: preset.id, endpoint: saved.endpoint || preset.endpoint, model: saved.model || (preset.id === 'embedded' ? 'local' : ''), key: ''};
  } catch {
    return {preset: 'embedded', endpoint: providerPreset('embedded').endpoint, model: 'local', key: ''};
  }
}

export function isLoopback(endpoint) {
  try {
    return ['localhost', '127.0.0.1', '[::1]', '::1'].includes(new URL(endpoint).hostname);
  } catch {
    return false;
  }
}

export function hostOf(endpoint) {
  try {
    return new URL(endpoint).host;
  } catch {
    return '';
  }
}

export function getProvider() {
  return {...state};
}

/** True when a run can be attempted (embedded engine additionally needs its run key). */
export function providerReady(p = state) {
  if (!p.endpoint || !p.model) return false;
  if (p.preset === 'embedded') return Boolean(p.key);
  return true;
}

/** Token budget for an agent run: local engines are limited by their context window. */
export function tokenBudget(p = state) {
  if (p.preset === 'embedded') return Math.max(4000, Math.floor((p.context || 8192) * 0.7));
  return 24000;
}

export function setProvider(partial) {
  state = {...state, ...partial};
  try {
    localStorage.setItem(KEY, JSON.stringify({preset: state.preset, endpoint: state.endpoint, model: state.model}));
  } catch {
    // Storage may be unavailable; the in-memory provider still works.
  }
  for (const fn of listeners) fn(getProvider());
}

export function onProvider(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function presets() {
  return PROVIDER_PRESETS;
}

export function lastModel() {
  try {
    return localStorage.getItem(LAST_MODEL) || '';
  } catch {
    return '';
  }
}

export function rememberModel(path) {
  try {
    localStorage.setItem(LAST_MODEL, path);
  } catch {
    // Ignore unavailable storage.
  }
}

export function describeProvider(p = state) {
  if (!p.endpoint) return t('No AI model connected');
  const host = hostOf(p.endpoint);
  if (p.preset === 'embedded') return p.key ? t('Local model ready · {host}', {host}) : t('Local model not started');
  return t(isLoopback(p.endpoint) ? 'Local server · {model} · {host}' : 'Cloud · {model} · {host}', {model: p.model || '?', host});
}

/**
 * Mirror the store into legacy inputs and back. Each field pair stays equal
 * regardless of which side the user edits.
 */
export function bindLegacyFields(doc = document) {
  const groups = [
    {endpoint: 'endpoint', model: 'model', key: 'key'},
    {preset: 'cpPreset', endpoint: 'cpEndpoint', model: 'cpModel', key: 'cpKey'}
  ];
  let applying = false;
  const write = p => {
    applying = true;
    for (const group of groups) {
      for (const [field, id] of Object.entries(group)) {
        const input = doc.getElementById(id);
        if (!input || input.value === (p[field] ?? '')) continue;
        input.value = p[field] ?? '';
        input.dispatchEvent(new Event(field === 'preset' ? 'change' : 'input'));
      }
    }
    applying = false;
  };
  for (const group of groups) {
    for (const [field, id] of Object.entries(group)) {
      const input = doc.getElementById(id);
      if (!input || field === 'preset') continue;
      input.addEventListener('input', () => {
        if (!applying && state[field] !== input.value) setProvider({[field]: input.value.trim?.() ?? input.value});
      });
    }
  }
  onProvider(write);
  write(state);
}
