import test from 'node:test';
import assert from 'node:assert/strict';
import {parseRules, confirmTransfer} from '../src/ui/helm-run.js';
import {markdown} from '../src/ui/agent-view.js';
import {pickQuant, parseRepo} from '../src/ui/model-hub.js';
import {emailRows} from '../src/ui/email-view.js';
import {isLoopback, providerReady} from '../src/ui/provider.js';
import {validateRules} from '../src/analysis.js';

test('parseRules extracts the last fenced JSON array and normalises fields', () => {
  const answer = 'Draft:\n```json\n[{"id":"x","field":"bogus","contains":"a"}]\n```\nFinal:\n```json\n[{"id":"custom-fwd 1","field":"action","contains":"Set-Mailbox","severity":"high","description":"Forwarding"},{"field":"ip","contains":""}]\n```';
  const rules = parseRules(answer);
  assert.equal(rules.length, 1);
  assert.equal(rules[0].id, 'CUSTOM-FWD-1');
  assert.equal(rules[0].severity, 'high');
  assert.doesNotThrow(() => validateRules(rules));
  assert.deepEqual(parseRules('no json here'), []);
  assert.equal(parseRules('[{"field":"sender","contains":"evil"}]')[0].severity, 'medium');
});

test('markdown escapes model output before formatting', () => {
  const html = markdown('# Title\n**bold** <img src=x onerror=alert(1)>\n- item');
  assert.ok(!html.includes('<img'));
  assert.ok(html.includes('&lt;img'));
  assert.ok(html.includes('<strong>bold</strong>'));
  assert.ok(html.includes('<li>item</li>'));
  const id = `${'a'.repeat(64)}:${'b'.repeat(64)}:12`;
  assert.ok(markdown(`see ${id}`).includes('data-evidence'));
});

test('pickQuant prefers single-file Q4_K_M and skips split files', () => {
  const files = [
    {path: 'm-Q8_0.gguf', bytes: 9}, {path: 'm-Q4_K_M-00001-of-00002.gguf', bytes: 2},
    {path: 'm-Q4_K_M.gguf', bytes: 5}, {path: 'mmproj-f16.gguf', bytes: 1}
  ];
  assert.equal(pickQuant(files).path, 'm-Q4_K_M.gguf');
  assert.equal(pickQuant([{path: 'a-Q8_0.gguf', bytes: 9}, {path: 'a-Q6_K.gguf', bytes: 6}]).path, 'a-Q6_K.gguf');
  assert.equal(pickQuant([]), null);
});

test('parseRepo accepts ids and Hugging Face links only', () => {
  assert.equal(parseRepo('Qwen/Qwen3-4B-GGUF'), 'Qwen/Qwen3-4B-GGUF');
  assert.equal(parseRepo('https://huggingface.co/Qwen/Qwen3-4B-GGUF/tree/main'), 'Qwen/Qwen3-4B-GGUF');
  assert.equal(parseRepo('https://evil.example/Qwen/x'), '');
  assert.equal(parseRepo('qwen3 gguf'), '');
});

test('emailRows sorts analysed messages by risk', () => {
  const rows = emailRows([
    {id: 'a', data: {email_analysis: {risk_score: 10}}},
    {id: 'b', data: {}},
    {id: 'c', data: {email_analysis: {risk_score: 80}, indicators: ['spf=fail']}}
  ]);
  assert.deepEqual(rows.map(r => r.event.id), ['c', 'a']);
});

test('provider helpers', () => {
  assert.ok(isLoopback('http://127.0.0.1:18081/v1/chat/completions'));
  assert.ok(!isLoopback('https://api.openai.com/v1/chat/completions'));
  assert.ok(!providerReady({preset: 'embedded', endpoint: 'http://127.0.0.1:1/v1', model: 'local', key: ''}));
  assert.ok(providerReady({preset: 'ollama', endpoint: 'http://127.0.0.1:11434/v1', model: 'qwen3', key: ''}));
  assert.equal(confirmTransfer({endpoint: 'http://localhost:1/v1'}, () => false), true);
  assert.equal(confirmTransfer({endpoint: 'https://api.example.test/v1'}, () => false), false);
});
