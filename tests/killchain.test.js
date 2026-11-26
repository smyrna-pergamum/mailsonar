import test from 'node:test';
import assert from 'node:assert/strict';
import {killChains} from '../src/killchain.js';

const ev = (id, time, sender, recipient) => ({id, timestamp: `2026-11-25T${time}:00Z`, sender, recipient, action: 'x', data: {}});
const events = [
  ev('e1', '08:45', 'no-reply@bad.example', 'elif@corp.test'),
  ev('e2', '09:02', 'elif@corp.test', ''),
  ev('e3', '09:06', 'elif@corp.test', ''),
  ev('e4', '09:30', 'elif@corp.test', 'finance@corp.test'),
  ev('e5', '08:00', 'elif@corp.test', '')
];

test('full four-stage chain is critical and ordered', () => {
  const findings = [
    {rule: 'MAIL-019', evidence: ['e1']}, {rule: 'MAIL-017', evidence: ['e2']},
    {rule: 'MAIL-002', evidence: ['e3']}, {rule: 'MAIL-025', evidence: ['e4']}
  ];
  const [chain] = killChains(events, findings);
  assert.equal(chain.rule, 'COR-004');
  assert.equal(chain.severity, 'critical');
  assert.deepEqual(chain.evidence, ['e1', 'e2', 'e3', 'e4']);
  assert.equal(chain.account, 'elif@corp.test');
});

test('chain without the access stage is not reported', () => {
  const findings = [{rule: 'MAIL-019', evidence: ['e1']}, {rule: 'MAIL-002', evidence: ['e3']}, {rule: 'MAIL-025', evidence: ['e4']}];
  assert.equal(killChains(events, findings).length, 0);
});

test('stages out of order are not chained', () => {
  // Manipulation at 08:00 happens before the sign-in; only access->action remains (2 stages).
  const findings = [{rule: 'MAIL-002', evidence: ['e5']}, {rule: 'MAIL-017', evidence: ['e2']}, {rule: 'MAIL-025', evidence: ['e4']}];
  assert.equal(killChains(events, findings).length, 0);
});
