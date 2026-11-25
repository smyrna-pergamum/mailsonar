// Pure helpers for the HELM agent studio UI. Kept dependency-free so they can be tested
// with the Node test runner and reused by the visual workflow editor.

export const PROVIDER_PRESETS = [
  {id: 'embedded', label: 'Embedded llama.cpp (managed)', endpoint: 'http://127.0.0.1:18081/v1/chat/completions', key: false, local: true, note: 'Load a GGUF model in Model Center first.'},
  {id: 'ollama', label: 'Ollama', endpoint: 'http://127.0.0.1:11434/v1/chat/completions', key: false, local: true, note: 'Ollama must already be running.'},
  {id: 'lmstudio', label: 'LM Studio', endpoint: 'http://127.0.0.1:1234/v1/chat/completions', key: false, local: true, note: 'Start the LM Studio local server.'},
  {id: 'vllm', label: 'vLLM', endpoint: 'http://127.0.0.1:8000/v1/chat/completions', key: false, local: true, note: 'vLLM OpenAI-compatible server.'},
  {id: 'openai', label: 'OpenAI', endpoint: 'https://api.openai.com/v1/chat/completions', key: true, local: false, note: 'Cloud provider. Evidence is minimized before tool results are returned.'},
  {id: 'openrouter', label: 'OpenRouter', endpoint: 'https://openrouter.ai/api/v1/chat/completions', key: true, local: false, note: 'Cloud provider. Evidence is minimized before tool results are returned.'},
  {id: 'custom', label: 'Custom OpenAI-compatible', endpoint: '', key: true, local: false, note: 'HTTPS is required except for loopback addresses.'}
];

export const NODE_PALETTE = [
  {kind: 'tool', label: 'Case tool', hint: 'Read-only query'},
  {kind: 'filter', label: 'Filter', hint: 'Exact field match'},
  {kind: 'aggregate', label: 'Aggregate', hint: 'Count by field'},
  {kind: 'detect', label: 'Detect', hint: 'Run detection rules'},
  {kind: 'validate', label: 'Evidence check', hint: 'Verify references'},
  {kind: 'visualize', label: 'Visualize', hint: 'Severity / timeline / graph'},
  {kind: 'branch', label: 'Branch', hint: 'Conditional path'},
  {kind: 'agent', label: 'AI agent', hint: 'Bounded analysis'},
  {kind: 'approval', label: 'Approval', hint: 'Human checkpoint'},
  {kind: 'report', label: 'Report', hint: 'Draft Markdown'}
];

const KINDS = new Set(NODE_PALETTE.map((n) => n.kind));

export function providerPreset(id) {
  return PROVIDER_PRESETS.find((p) => p.id === id) ?? PROVIDER_PRESETS.at(-1);
}

export function isLoopbackEndpoint(endpoint) {
  try {
    const url = new URL(endpoint);
    return ['localhost', '127.0.0.1', '[::1]', '::1'].includes(url.hostname);
  } catch {
    return false;
  }
}

export function formatBytes(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const index = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  const value = n / Math.pow(1024, index);
  return `${value >= 100 || index === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[index]}`;
}

export function formatMs(ms) {
  const n = Number(ms);
  if (!Number.isFinite(n) || n < 0) return 'Not Evaluated';
  return n < 1000 ? `${Math.round(n)} ms` : `${(n / 1000).toFixed(2)} s`;
}

export function formatPercent(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 'Not Evaluated';
  return `${(n * 100).toFixed(1)}%`;
}

export function clamp(value, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return min;
  return Math.min(max, Math.max(min, n));
}

export function safeJson(text, fallback = null) {
  try {
    return JSON.parse(text);
  } catch {
    return fallback;
  }
}

export function nodeDefaults(kind, id = 'n1') {
  const base = {id, kind, tool: '', args: {}, after: [], when: null, label: kind, x: 60, y: 60};
  switch (kind) {
    case 'tool':
      return {...base, label: 'Case tool', tool: 'list_events', args: {limit: 25}};
    case 'filter':
      return {...base, label: 'Filter', args: {field: 'sender', value: '', limit: 25}};
    case 'aggregate':
      return {...base, label: 'Aggregate', args: {field: 'action', limit: 10}};
    case 'detect':
      return {...base, label: 'Detect rules', args: {}};
    case 'validate':
      return {...base, label: 'Evidence check', args: {}};
    case 'visualize':
      return {...base, label: 'Visualize', args: {kind: 'severity'}};
    case 'report':
      return {...base, label: 'Draft report', args: {title: 'MailSonar workflow report'}};
    case 'approval':
      return {...base, label: 'Approval', args: {message: 'Review the workflow results before continuing.'}};
    case 'branch':
      return {...base, label: 'Branch', args: {condition: {result: '', path: 'total', op: 'gt', value: 0}}};
    case 'agent':
      return {...base, label: 'HELM agent', args: {prompt: 'Summarize the most important findings, evidence gaps and uncertainty.'}};
    default:
      return base;
  }
}

export function newWorkflow(name = 'Untitled workflow') {
  const stamp = Date.now().toString(36);
  return {
    id: `wf-${stamp}`,
    name,
    version: 1,
    created_at: '',
    updated_at: '',
    nodes: [
      {...nodeDefaults('tool', 'n1'), x: 60, y: 80, label: 'List records'},
      {...nodeDefaults('detect', 'n2'), after: ['n1'], x: 320, y: 80, label: 'Detect rules'},
      {...nodeDefaults('visualize', 'n3'), after: ['n2'], x: 580, y: 80, label: 'Severity view'}
    ]
  };
}

export function sampleWorkflow() {
  return {
    id: 'wf-read-only-triage',
    name: 'Read-only triage',
    version: 1,
    created_at: '',
    updated_at: '',
    nodes: [
      {...nodeDefaults('tool', 'n1'), tool: 'event_stats', args: {}, x: 40, y: 80, label: 'Case statistics'},
      {...nodeDefaults('detect', 'n2'), after: ['n1'], x: 300, y: 80, label: 'Detection rules'},
      {...nodeDefaults('visualize', 'n3'), after: ['n2'], args: {kind: 'severity'}, x: 560, y: 20, label: 'Severity chart'},
      {...nodeDefaults('validate', 'n4'), after: ['n2'], x: 560, y: 170, label: 'Evidence references'},
      {...nodeDefaults('report', 'n5'), after: ['n3', 'n4'], x: 820, y: 90, label: 'Draft report'}
    ]
  };
}

export function nextNodeId(workflow) {
  const used = new Set((workflow?.nodes ?? []).map((n) => n.id));
  let index = 1;
  while (used.has(`n${index}`)) index++;
  return `n${index}`;
}

export function addNode(workflow, kind, position = {}) {
  const node = nodeDefaults(kind, nextNodeId(workflow));
  node.x = Number.isFinite(position.x) ? position.x : 80 + (workflow.nodes.length % 5) * 220;
  node.y = Number.isFinite(position.y) ? position.y : 80 + Math.floor(workflow.nodes.length / 5) * 130;
  workflow.nodes.push(node);
  return node;
}

export function removeNode(workflow, id) {
  workflow.nodes = workflow.nodes.filter((n) => n.id !== id);
  for (const node of workflow.nodes) {
    node.after = node.after.filter((dep) => dep !== id);
  }
}

export function connectNodes(workflow, from, to, when = null) {
  if (!from || !to || from === to) return false;
  const node = workflow.nodes.find((n) => n.id === to);
  const source = workflow.nodes.find((n) => n.id === from);
  if (!node || !source) return false;
  if (!node.after.includes(from)) node.after.push(from);
  if (when === 'true' || when === 'false') node.when = when;
  return true;
}

export function disconnectNodes(workflow, from, to) {
  const node = workflow.nodes.find((n) => n.id === to);
  if (!node) return false;
  node.after = node.after.filter((dep) => dep !== from);
  if (!node.after.length) node.when = null;
  return true;
}

export function topologicalOrder(workflow) {
  const nodes = workflow?.nodes ?? [];
  const done = new Set();
  const order = [];
  const pending = [...nodes];
  while (pending.length) {
    const index = pending.findIndex((n) => (n.after ?? []).every((dep) => done.has(dep)));
    if (index < 0) return {ok: false, errors: ['Workflow contains a cycle or missing dependency'], order: []};
    const node = pending.splice(index, 1)[0];
    done.add(node.id);
    order.push(node.id);
  }
  return {ok: true, errors: [], order};
}

export function validateWorkflowLocal(workflow) {
  const errors = [];
  const nodes = workflow?.nodes;
  if (!Array.isArray(nodes) || nodes.length < 1 || nodes.length > 32) {
    errors.push('Workflow must contain 1 to 32 nodes');
    return {ok: false, errors, order: []};
  }
  if (!workflow.name || workflow.name.length > 120) errors.push('Workflow name is required');
  const ids = new Set();
  for (const node of nodes) {
    if (!/^[-a-zA-Z0-9_]{1,40}$/.test(node.id ?? '')) errors.push(`Invalid node id: ${node.id}`);
    if (ids.has(node.id)) errors.push(`Duplicate node id: ${node.id}`);
    ids.add(node.id);
    if (!KINDS.has(node.kind)) errors.push(`Unknown node kind: ${node.kind}`);
    if (!node.args || typeof node.args !== 'object' || Array.isArray(node.args)) errors.push(`Node ${node.id} args must be an object`);
    if (node.when !== null && node.when !== undefined && !['true', 'false'].includes(node.when)) errors.push(`Node ${node.id} when must be true or false`);
    for (const dep of node.after ?? []) {
      if (dep === node.id) errors.push(`Node ${node.id} depends on itself`);
      else if (!nodes.some((n) => n.id === dep)) errors.push(`Node ${node.id} has a missing dependency: ${dep}`);
    }
    if (node.kind === 'branch') {
      const condition = node.args?.condition;
      if (!condition || typeof condition !== 'object') errors.push(`Branch ${node.id} requires a condition`);
      else if (!(node.after ?? []).includes(condition.result)) errors.push(`Branch ${node.id} condition must reference a dependency`);
    }
    if (node.kind === 'approval' && !node.args?.message) errors.push(`Approval ${node.id} requires a message`);
    if (node.kind === 'agent' && (!node.args?.prompt || node.args.prompt.length < 3)) errors.push(`Agent ${node.id} requires a prompt`);
  }
  if (errors.length) return {ok: false, errors, order: []};
  return topologicalOrder(workflow);
}

export function workflowFromText(text) {
  const cleaned = String(text ?? '').trim().replace(/^```(?:json)?/i, '').replace(/```$/, '').trim();
  const parsed = JSON.parse(cleaned);
  if (!parsed || !Array.isArray(parsed.nodes)) throw new Error('Workflow must contain a nodes array');
  return parsed;
}

export function nodeSummary(node) {
  if (!node) return '';
  if (node.kind === 'tool') return node.tool || 'tool';
  if (node.kind === 'filter') return `${node.args?.field ?? 'field'} = ${String(node.args?.value ?? '').slice(0, 24)}`;
  if (node.kind === 'aggregate') return `count by ${node.args?.field ?? 'field'}`;
  if (node.kind === 'visualize') return `view: ${node.args?.kind ?? 'severity'}`;
  if (node.kind === 'report') return String(node.args?.title ?? 'report').slice(0, 32);
  if (node.kind === 'branch') return `${node.args?.condition?.result ?? '?'} ${node.args?.condition?.op ?? ''} ${node.args?.condition?.value ?? ''}`;
  if (node.kind === 'approval') return 'human checkpoint';
  if (node.kind === 'agent') return 'bounded AI analysis';
  return node.kind;
}

export function workflowForBackend(workflow) {
  return {
    ...workflow,
    nodes: (workflow.nodes ?? []).map((node) => ({
      ...node,
      after: [...(node.after ?? [])],
      when: node.when === 'true' || node.when === 'false' ? node.when : null,
      args: node.args && typeof node.args === 'object' && !Array.isArray(node.args) ? node.args : {}
    }))
  };
}
