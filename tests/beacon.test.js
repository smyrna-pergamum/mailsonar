import {test} from 'node:test';
import assert from 'node:assert/strict';
import {localAnswer, askSelected, askAgent} from '../src/beacon/core.js';

const base = {
  question: 'Review',
  records: [{id: 'x'}],
  config: {endpoint: 'https://example.test/v1/chat/completions', model: 'test'},
  approve: async () => true,
  ask: async () => 'ok'
};

test('offline topic', () => assert.equal(localAnswer('How do I import logs?').tab, 'explorer'));
test('unknown topic', () => assert.match(localAnswer('xyz').text, /No matching/));
test('summary', () => assert.match(localAnswer('Case summary', {events: 12}).text, /12 events/));
test('agent help points at the HELM studio', () => assert.equal(localAnswer('How do I use HELM?').tab, 'copilot'));

test('reject empty selection', async () => assert.rejects(askSelected({...base, records: []}), /Select/));
test('reject excessive selection', async () => assert.rejects(askSelected({...base, records: Array(26).fill({})}), /Select/));
test('reject remote HTTP', async () => assert.rejects(askSelected({...base, config: {...base.config, endpoint: 'http://example.test'}}), /HTTPS/));
test('reject URL credentials', async () => assert.rejects(askSelected({...base, config: {...base.config, endpoint: 'https://a:b@example.test'}}), /HTTPS/));
test('reject missing endpoint', async () => assert.rejects(askSelected({...base, config: {model: 'test'}}), /endpoint/));
test('deny consent prevents call', async () => assert.equal(await askSelected({...base, approve: async () => false, ask: () => assert.fail()}), null));
test('approved request uses host', async () => assert.equal(await askSelected(base), 'ok'));
test('snapshot isolates changes during approval', async () => {
  const records = [{id: 'original'}];
  await askSelected({...base, records, approve: async () => { records[0].id = 'changed'; return true; }, ask: async (c, q, r) => assert.equal(r[0].id, 'original')});
});

const agentBase = {
  question: 'Triage the case',
  counts: {events: 10, findings: 2},
  config: {endpoint: 'http://127.0.0.1:18081/v1/chat/completions', model: 'local'},
  approve: async () => true,
  run: async () => 'agent-ok'
};

test('agent requires evidence', async () => assert.rejects(askAgent({...agentBase, counts: {events: 0}}), /Import evidence/));
test('agent rejects remote HTTP', async () => assert.rejects(askAgent({...agentBase, config: {...agentBase.config, endpoint: 'http://example.test'}}), /HTTPS/));
test('agent deny consent prevents run', async () => assert.equal(await askAgent({...agentBase, approve: async () => false, run: () => assert.fail()}), null));
test('agent approved request uses host', async () => assert.equal(await askAgent(agentBase), 'agent-ok'));
