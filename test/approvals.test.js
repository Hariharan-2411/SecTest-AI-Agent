import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApprovalBroker } from '../lib/approvals.js';

function memStore() {
  const rows = new Map();
  return {
    all: () => [...rows.values()],
    upsert: (r) => (rows.set(r.id, { ...(rows.get(r.id) || {}), ...r }), r),
    get: (id) => rows.get(id) || null,
  };
}

test('approve resolves the request to true and records status', async () => {
  const store = memStore();
  const seen = [];
  const b = createApprovalBroker({ store, notify: (r) => seen.push(r) });
  const p = b.request({ tool: 'nuclei', target: 'app.example.com' });
  const [id] = b.pendingIds();
  assert.equal(store.get(id).status, 'pending');
  assert.equal(seen.length, 1);
  assert.ok(b.approve(id, 'tester'));
  assert.equal(await p, true);
  assert.equal(store.get(id).status, 'approve');
  assert.equal(store.get(id).decidedBy, 'tester');
});

test('deny resolves to false', async () => {
  const store = memStore();
  const b = createApprovalBroker({ store });
  const p = b.request({ tool: 'sqlmap', target: 'app.example.com' });
  const [id] = b.pendingIds();
  b.deny(id);
  assert.equal(await p, false);
  assert.equal(store.get(id).status, 'deny');
});

test('timeout auto-denies (fail-safe)', async () => {
  const store = memStore();
  // Deterministic timer we trigger by hand.
  let fire;
  const b = createApprovalBroker({
    store,
    timeoutMs: 123,
    setTimer: (fn) => { fire = fn; return { unref() {} }; },
    clearTimer: () => {},
  });
  const p = b.request({ tool: 'nmap', target: 'app.example.com' });
  const [id] = b.pendingIds();
  fire(); // simulate the timeout firing
  assert.equal(await p, false);
  assert.equal(store.get(id).status, 'timeout');
});

test('records request and decision to the audit log when one is injected', async () => {
  const store = memStore();
  const events = [];
  const audit = { record: (type, detail, actor) => events.push({ type, detail, actor }) };
  const b = createApprovalBroker({ store, audit });
  const p = b.request({ tool: 'sqlmap', target: 'app.example.com', risk: 'destructive' });
  const [id] = b.pendingIds();
  b.approve(id, 'tester');
  await p;
  assert.deepEqual(events.map((e) => e.type), ['approval.requested', 'approval.approve']);
  assert.equal(events[0].detail.risk, 'destructive');
  assert.equal(events[1].actor, 'tester');
});

test('settling an unknown/already-settled id is a no-op', async () => {
  const store = memStore();
  const b = createApprovalBroker({ store });
  assert.equal(b.approve('nope'), false);
  const p = b.request({ tool: 'subfinder', target: 'a.example.com' });
  const [id] = b.pendingIds();
  assert.ok(b.deny(id));
  assert.equal(b.approve(id), false); // second settle ignored
  assert.equal(await p, false);
});
