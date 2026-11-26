import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {LESSONS, checkAnswer} from '../src/ui/lessons.js';
import {killChains} from '../src/killchain.js';
import {normalize} from '../src/advanced.js';

// Fixtures are the real Rust parser output (cargo test demo_write_preview_fixture -- --ignored).
const load = name => JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));
function caseOf(prefix) {
  const evidence = load(`${prefix}-evidence.json`).map(f => ({...f, events: f.events.map(normalize)}));
  const events = evidence.flatMap(f => f.events);
  const base = load(`${prefix}-findings.json`);
  return {evidence, events, findings: [...base, ...killChains(events, base)], rules: []};
}
const cases = {'bec-demo': caseOf('demo'), 'github-baseline': caseOf('baseline')};

test('every lesson question has a computable answer on its dataset', () => {
  for (const lesson of LESSONS) {
    lesson.steps.forEach((step, i) => {
      if (step.type === 'task') return;
      const expected = String(step.answer(cases[lesson.dataset]));
      assert.ok(expected.length > 0, `${lesson.id}#${i + 1} has no answer`);
      if (step.type === 'choice') {
        assert.ok(checkAnswer(step, step.options.find(o => checkAnswer(step, o, cases[lesson.dataset]).ok) ?? '', cases[lesson.dataset]).ok, `${lesson.id}#${i + 1}: no option matches "${expected}"`);
        const correct = step.options.filter(o => checkAnswer(step, o, cases[lesson.dataset]).ok);
        assert.equal(correct.length, 1, `${lesson.id}#${i + 1}: ${correct.length} options accepted`);
      } else {
        assert.ok(checkAnswer(step, expected, cases[lesson.dataset]).ok);
        assert.ok(!checkAnswer(step, 'definitely wrong', cases[lesson.dataset]).ok);
      }
    });
  }
});

test('rule-writing task checks the active rules', () => {
  const step = LESSONS.find(l => l.id === 'rule').steps[0];
  const c = cases['bec-demo'];
  assert.equal(checkAnswer(step, '', {...c, rules: []}).ok, false);
  assert.equal(checkAnswer(step, '', {...c, rules: [{field: 'action', contains: 'Set-Mailbox'}]}).ok, true);
});
