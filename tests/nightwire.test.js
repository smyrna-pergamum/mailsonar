import test from 'node:test';
import assert from 'node:assert/strict';
import {
  aiEvaluationMetrics,
  formatDuration,
  formatPercent,
  hourlyBuckets,
  iocTypeCounts,
  matchedIndicators,
  median,
  mitreRows,
  severityCounts,
  severityKey
} from '../src/nightwire-data.js';

const event = (id, timestamp) => ({ id, timestamp });

test('hourly buckets count dated events and ignore invalid timestamps', () => {
  const series = hourlyBuckets([
    event('a', '2026-01-01T10:01:00Z'),
    event('b', '2026-01-01T10:59:00Z'),
    event('c', '2026-01-01T11:00:00Z'),
    event('d', 'not-a-date')
  ]);
  assert.deepEqual(series, [
    ['2026-01-01T10:00Z', 2],
    ['2026-01-01T11:00Z', 1]
  ]);
});

test('hourly bucket limit keeps the latest buckets', () => {
  const events = Array.from({ length: 30 }, (_, index) => event(String(index), `2026-01-01T${String(index % 24).padStart(2, '0')}:00:00Z`));
  assert.equal(hourlyBuckets(events, 5).length, 5);
});

test('severity counts are computed and unknown values are grouped', () => {
  const rows = severityCounts([{ severity: 'high' }, { severity: 'high' }, { severity: 'critical' }, { severity: 'bogus' }]);
  const byName = Object.fromEntries(rows.map((row) => [row.severity, row.count]));
  assert.equal(byName.high, 2);
  assert.equal(byName.critical, 1);
  assert.equal(byName.unknown, 1);
  assert.equal(byName.low, 0);
  assert.equal(severityKey('HIGH'), 'high');
});

test('MITRE counts fold sub-techniques into parent techniques', () => {
  const rows = mitreRows([
    { attack: ['T1110.001', 'T1566'] },
    { attack: ['T1114.003'] },
    { attack: [] }
  ]);
  const techniques = Object.fromEntries(rows.flatMap((row) => row.techniques.map((technique) => [technique.id, technique.count])));
  assert.equal(techniques.T1110, 1);
  assert.equal(techniques.T1566, 1);
  assert.equal(techniques.T1114, 1);
  assert.equal(techniques.T1078, 0);
});

test('IOC types and local matches are derived from loaded indicators and findings', () => {
  const types = iocTypeCounts([
    { type: 'ipv4-addr', value: '192.0.2.1' },
    { type: 'domain-name', value: 'evil.test' },
    { type: 'ipv4-addr', value: '192.0.2.2' }
  ]);
  assert.deepEqual(types, [
    { type: 'ipv4-addr', count: 2 },
    { type: 'domain-name', count: 1 }
  ]);
  const matches = matchedIndicators([
    { rule: 'TI-001', description: 'IOC match (ipv4-addr): 192.0.2.1; source misp-1' },
    { rule: 'TI-001', description: 'IOC match (ipv4-addr): 192.0.2.1; source misp-1' },
    { rule: 'TI-001', description: 'unexpected format' }
  ]);
  assert.equal(matches.length, 1);
  assert.equal(matches[0].count, 2);
  assert.equal(matches[0].value, '192.0.2.1');
});

test('AI evaluation metrics report Not Evaluated when no runs exist', () => {
  const metrics = aiEvaluationMetrics([]);
  assert.equal(metrics.total, 0);
  assert.equal(metrics.referenceRate, null);
  assert.equal(formatPercent(metrics.referenceRate), 'Not Evaluated');
  assert.equal(formatDuration(metrics.medianMs), 'Not Evaluated');
});

test('AI evaluation metrics aggregate measured session runs', () => {
  const metrics = aiEvaluationMetrics([
    { ok: true, ms: 100, events: 5, model: 'm', mode: 'selected', jsonValid: true, validation: { accepted: [{}, {}], rejected: [{}] } },
    { ok: true, ms: 300, events: 5, model: 'm', mode: 'batch', jsonValid: true, validation: { accepted: [{}], rejected: [] } },
    { ok: false, ms: 200, events: 2, model: 'm', mode: 'batch' }
  ]);
  assert.equal(metrics.total, 3);
  assert.equal(metrics.completed, 2);
  assert.equal(metrics.failed, 1);
  assert.equal(metrics.eventsSent, 12);
  assert.equal(metrics.medianMs, 200);
  assert.equal(metrics.accepted, 3);
  assert.equal(metrics.rejected, 1);
  assert.equal(metrics.referenceRate, 0.75);
  assert.equal(metrics.jsonMeasured, 2);
  assert.equal(metrics.jsonRate, 1);
});

test('median handles even and odd samples', () => {
  assert.equal(median([3, 1, 2]), 2);
  assert.equal(median([4, 1, 3, 2]), 2.5);
  assert.equal(median([]), null);
});
