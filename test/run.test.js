import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toRiskPolicy, createRunner, suppressFromAlerts } from '../lib/run.js';

function memStore() {
  const rows = new Map();
  return {
    all: () => [...rows.values()],
    get: (id) => rows.get(id) || null,
    upsert: (r) => (rows.set(r.id, { ...(rows.get(r.id) || {}), ...r }), r),
  };
}

test('safe-only policy denies active and destructive', () => {
  assert.deepEqual(toRiskPolicy({ allowActive: false }), { safe: 'allow', active: 'deny', destructive: 'deny' });
});
test('active-allowed gates active for a human, destructive stays denied', () => {
  assert.deepEqual(toRiskPolicy({ allowActive: true }), { safe: 'allow', active: 'needs_approval', destructive: 'deny' });
});
test('destructive opt-in gates destructive for a human too', () => {
  assert.deepEqual(toRiskPolicy({ allowActive: true, allowDestructive: true }), { safe: 'allow', active: 'needs_approval', destructive: 'needs_approval' });
});

test('FP filter suppresses weak false positives but never a strong/confirmed finding', () => {
  const fp = { verdict: 'false_positive', reason: 'thin' };
  // weak + flagged → suppressed
  assert.equal(suppressFromAlerts({ severity: 'low', confidence: 30 }, fp), true);
  // confirmed SQLi (high sev, conf 75) flagged FP → MUST NOT be suppressed (the live-run bug)
  assert.equal(suppressFromAlerts({ severity: 'high', confidence: 75 }, fp), false);
  assert.equal(suppressFromAlerts({ severity: 'critical' }, fp), false);
  assert.equal(suppressFromAlerts({ confidence: 70 }, fp), false);
  // not flagged FP → never suppressed regardless of strength
  assert.equal(suppressFromAlerts({ severity: 'low' }, { verdict: 'likely' }), false);
  assert.equal(suppressFromAlerts({ severity: 'low' }, null), false);
});

test('an engaged kill-switch halts the run before any scan dispatch', async () => {
  const runs = memStore();
  const events = [];
  const audit = { record: (type) => events.push(type) };
  const killswitch = { engaged: () => true, assert() { throw new Error('kill_switch_engaged'); } };
  const runner = createRunner({
    env: { AGENT_URL: 'http://agent.invalid', AGENT_TOKEN: 't' },
    audit, killswitch, runs, llm: { clients: [], chat: async () => ({}) },
  });
  const r = await runner.runEngagement({ name: 'halt-me', scope: { inScope: [], outOfScope: [] }, policy: {}, evidenceMode: 'light' });
  assert.equal(r.status, 'halted');
  assert.equal(runs.get(r.id).status, 'halted');
  assert.ok(events.includes('run.halted'));
});
