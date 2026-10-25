import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createMonitor } from '../lib/monitor.js';

function memStore() {
  const rows = new Map();
  return {
    all: () => [...rows.values()],
    get: (id) => rows.get(id) || null,
    upsert: (r) => (rows.set(r.id, { ...(rows.get(r.id) || {}), ...r }), r),
  };
}

test('schedule() persists an active monitor and arms a timer at the interval', () => {
  const store = memStore();
  const timers = [];
  const runner = { runEngagement: async () => ({ id: 'run_x', ranked: [] }) };
  const m = createMonitor({ runner, store, setTimer: (fn, ms) => { timers.push({ fn, ms }); return timers.length; }, clearTimer: () => {} });
  const mon = m.schedule({ name: 'nightly' }, 60000);
  assert.equal(mon.status, 'active');
  assert.equal(mon.intervalMs, 60000);
  assert.equal(store.get(mon.id).status, 'active');
  assert.equal(timers.length, 1);
  assert.equal(timers[0].ms, 60000);
});

test('a cycle runs the engagement and audits new-vs-seen counts', async () => {
  const store = memStore();
  const events = [];
  const audit = { record: (type, detail) => events.push({ type, detail }) };
  const ranked = [{ status: 'new' }, { status: 'seen' }, { status: 'new' }];
  const runner = { runEngagement: async () => ({ id: 'run_1', ranked }) };
  const m = createMonitor({ runner, store, audit, setTimer: () => 1, clearTimer: () => {} });
  const mon = m.schedule({ name: 'n' }, 1000);
  const r = await m.runCycle(mon.id);
  assert.equal(r.runId, 'run_1');
  assert.equal(r.new, 2);
  const cyc = events.find((e) => e.type === 'monitor.cycle');
  assert.equal(cyc.detail.new, 2);
  assert.equal(cyc.detail.seen, 1);
  assert.equal(store.get(mon.id).runs, 1);
});

test('a cycle builds a recon digest of the new findings and sends it via the bot', async () => {
  const store = memStore();
  const ranked = [
    { id: 'a', status: 'new', host: 'app.example.com', title: 'New JWT' },
    { id: 'b', status: 'seen', host: 'app.example.com', title: 'Old thing' },
  ];
  const runner = { runEngagement: async () => ({ id: 'run_9', ranked }) };
  const sent = [];
  const bot = { notifyText: async (t) => sent.push(t) };
  // Inject the digest fns so the test stays pure (no bundle/signals dependency).
  const buildDigest = (delta) => ({ empty: delta.newFindings.length === 0, summary: `${delta.newFindings.length} new`, newFindings: delta.newFindings });
  const formatDigest = (d) => `DIGEST: ${d.summary}`;
  const m = createMonitor({ runner, store, bot, buildDigest, formatDigest, setTimer: () => 1, clearTimer: () => {} });
  const mon = m.schedule({ name: 'n', scope: {} }, 1000);
  await m.runCycle(mon.id);
  assert.equal(sent.length, 1);
  assert.match(sent[0], /DIGEST: 1 new/);           // only the 1 NEW finding counted
  assert.ok(store.get(mon.id).lastDigest);           // digest persisted on the monitor
});

test('a cycle with no new findings sends no digest (quiet)', async () => {
  const store = memStore();
  const runner = { runEngagement: async () => ({ id: 'run_q', ranked: [{ id: 'b', status: 'seen' }] }) };
  const sent = [];
  const bot = { notifyText: async (t) => sent.push(t) };
  const buildDigest = (delta) => ({ empty: delta.newFindings.length === 0, summary: 'none', newFindings: delta.newFindings });
  const formatDigest = (d) => `DIGEST: ${d.summary}`;
  const m = createMonitor({ runner, store, bot, buildDigest, formatDigest, setTimer: () => 1, clearTimer: () => {} });
  const mon = m.schedule({ name: 'n' }, 1000);
  await m.runCycle(mon.id);
  assert.equal(sent.length, 0); // empty digest → stay quiet
});

test('a cycle is skipped (engagement never runs) while the kill-switch is engaged', async () => {
  const store = memStore();
  const events = [];
  const audit = { record: (type) => events.push(type) };
  let ran = false;
  const runner = { runEngagement: async () => { ran = true; return { id: 'r', ranked: [] }; } };
  const killswitch = { engaged: () => true };
  const m = createMonitor({ runner, store, audit, killswitch, setTimer: () => 1, clearTimer: () => {} });
  const mon = m.schedule({ name: 'n' }, 1000);
  const r = await m.runCycle(mon.id);
  assert.equal(ran, false);
  assert.equal(r.skipped, true);
  assert.ok(events.includes('monitor.skipped'));
});

test('stop() clears the timer, marks the monitor stopped, and drops it from list()', () => {
  const store = memStore();
  let cleared = 0;
  const runner = { runEngagement: async () => ({ id: 'r', ranked: [] }) };
  const m = createMonitor({ runner, store, setTimer: () => 42, clearTimer: () => { cleared += 1; } });
  const mon = m.schedule({ name: 'n' }, 1000);
  assert.equal(m.list().length, 1);
  m.stop(mon.id);
  assert.equal(cleared, 1);
  assert.equal(store.get(mon.id).status, 'stopped');
  assert.equal(m.list().length, 0); // list = active only
});

test('resume() re-arms timers for persisted active monitors after a restart', () => {
  const store = memStore();
  store.upsert({ id: 'mon_1', name: 'n', engagement: { name: 'n' }, intervalMs: 1000, status: 'active' });
  store.upsert({ id: 'mon_2', name: 'old', engagement: { name: 'old' }, intervalMs: 1000, status: 'stopped' });
  let armed = 0;
  const runner = { runEngagement: async () => ({ id: 'r', ranked: [] }) };
  const m = createMonitor({ runner, store, setTimer: () => { armed += 1; return armed; }, clearTimer: () => {} });
  m.resume();
  assert.equal(armed, 1); // only the active one
});
