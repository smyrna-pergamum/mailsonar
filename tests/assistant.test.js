import test from 'node:test';
import assert from 'node:assert/strict';
import {
  NODE_PALETTE,
  PROVIDER_PRESETS,
  addNode,
  clamp,
  connectNodes,
  disconnectNodes,
  formatBytes,
  formatMs,
  newWorkflow,
  nodeDefaults,
  nodeSummary,
  providerPreset,
  removeNode,
  sampleWorkflow,
  topologicalOrder,
  validateWorkflowLocal,
  workflowForBackend,
  workflowFromText
} from '../src/assistant-data.js';

test('provider presets include local and cloud OpenAI-compatible targets', () => {
  const ids = PROVIDER_PRESETS.map((p) => p.id);
  for (const id of ['embedded', 'ollama', 'lmstudio', 'vllm', 'openai', 'openrouter', 'custom']) {
    assert.ok(ids.includes(id), `missing ${id}`);
  }
  assert.equal(providerPreset('openai').key, true);
  assert.equal(providerPreset('embedded').local, true);
  assert.equal(providerPreset('does-not-exist').id, 'custom');
});

test('number and byte formatting never invent values', () => {
  assert.equal(formatBytes(0), '0 B');
  assert.equal(formatBytes(1024), '1.0 KB');
  assert.equal(formatBytes(-1), '0 B');
  assert.equal(formatBytes('nonsense'), '0 B');
  assert.equal(formatMs(45), '45 ms');
  assert.equal(formatMs(2500), '2.50 s');
  assert.equal(formatMs(undefined), 'Not Evaluated');
  assert.equal(clamp(9, 1, 5), 5);
  assert.equal(clamp('x', 1, 5), 1);
});

test('node palette covers bounded workflow node kinds', () => {
  const kinds = NODE_PALETTE.map((n) => n.kind);
  assert.deepEqual(kinds, [
    'tool',
    'filter',
    'aggregate',
    'detect',
    'validate',
    'visualize',
    'branch',
    'agent',
    'approval',
    'report'
  ]);
  assert.equal(nodeDefaults('tool').tool, 'list_events');
  assert.equal(nodeDefaults('approval').args.message.length > 0, true);
  assert.equal(nodeDefaults('agent').args.prompt.length > 0, true);
});

test('new and sample workflows validate without cycles', () => {
  const fresh = newWorkflow('Triage');
  const result = validateWorkflowLocal(fresh);
  assert.equal(result.ok, true, result.errors.join('; '));
  assert.equal(result.order.length, fresh.nodes.length);

  const sample = sampleWorkflow();
  const sampleResult = validateWorkflowLocal(sample);
  assert.equal(sampleResult.ok, true, sampleResult.errors.join('; '));
  assert.equal(sampleResult.order.at(-1), 'n5');
});

test('cycles and missing dependencies are rejected', () => {
  const cycle = newWorkflow('Cycle');
  cycle.nodes = [
    {...nodeDefaults('detect', 'a'), after: ['b']},
    {...nodeDefaults('detect', 'b'), after: ['a']}
  ];
  assert.equal(validateWorkflowLocal(cycle).ok, false);

  const missing = newWorkflow('Missing');
  missing.nodes = [{...nodeDefaults('detect', 'a'), after: ['ghost']}];
  const result = validateWorkflowLocal(missing);
  assert.equal(result.ok, false);
  assert.match(result.errors.join(' '), /missing dependency/);
});

test('topological order respects dependencies', () => {
  const workflow = newWorkflow('Order');
  workflow.nodes = [
    {...nodeDefaults('detect', 'c')},
    {...nodeDefaults('visualize', 'b'), after: ['c']},
    {...nodeDefaults('report', 'a'), after: ['b']}
  ];
  const result = topologicalOrder(workflow);
  assert.equal(result.ok, true);
  assert.deepEqual(result.order, ['c', 'b', 'a']);
});

test('branch and approval nodes require configuration', () => {
  const branch = newWorkflow('Branch');
  branch.nodes = [nodeDefaults('branch', 'a')];
  assert.equal(validateWorkflowLocal(branch).ok, false);

  const approval = newWorkflow('Approval');
  approval.nodes = [{...nodeDefaults('approval', 'a'), args: {}}];
  assert.equal(validateWorkflowLocal(approval).ok, false);
});

test('add, connect and remove nodes keep dependencies consistent', () => {
  const workflow = newWorkflow('Graph');
  const node = addNode(workflow, 'report', {x: 40, y: 50});
  assert.equal(node.x, 40);
  assert.equal(node.y, 50);
  assert.equal(connectNodes(workflow, 'n1', node.id), true);
  assert.equal(connectNodes(workflow, 'n1', node.id), true);
  assert.deepEqual(workflow.nodes.find((n) => n.id === node.id).after, ['n1']);
  assert.equal(connectNodes(workflow, node.id, node.id), false);
  removeNode(workflow, 'n1');
  assert.equal(workflow.nodes.some((n) => n.id === 'n1'), false);
  assert.equal(workflow.nodes.find((n) => n.id === node.id).after.includes('n1'), false);
});

test('branch connections carry true and false labels', () => {
  const workflow = newWorkflow('Branch connect');
  assert.equal(connectNodes(workflow, 'n1', 'n2', 'false'), true);
  assert.equal(workflow.nodes.find((n) => n.id === 'n2').when, 'false');
  assert.equal(disconnectNodes(workflow, 'n1', 'n2'), true);
  assert.equal(workflow.nodes.find((n) => n.id === 'n2').when, null);
});

test('workflow JSON parsing strips a single markdown fence', () => {
  const parsed = workflowFromText('```json\n{"id":"wf-a","name":"A","nodes":[]}\n```');
  assert.equal(parsed.id, 'wf-a');
  assert.throws(() => workflowFromText('not json'), /JSON/);
  assert.throws(() => workflowFromText('{"id":"x"}'), /nodes/);
});

test('backend payload normalizes optional fields', () => {
  const workflow = newWorkflow('Normalize');
  workflow.nodes[0].when = 'maybe';
  workflow.nodes[0].args = null;
  const payload = workflowForBackend(workflow);
  assert.equal(payload.nodes[0].when, null);
  assert.deepEqual(payload.nodes[0].args, {});
  assert.notEqual(payload.nodes[0].after, workflow.nodes[0].after);
  assert.deepEqual(payload.nodes[0].after, workflow.nodes[0].after);
});

test('node summaries are stable and bounded', () => {
  assert.equal(nodeSummary({kind: 'filter', args: {field: 'sender', value: 'a@b.test'}}), 'sender = a@b.test');
  assert.equal(nodeSummary({kind: 'visualize', args: {kind: 'timeline'}}), 'view: timeline');
  assert.equal(nodeSummary({kind: 'approval'}), 'human checkpoint');
  assert.equal(nodeSummary(null), '');
});
