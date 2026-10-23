import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createAuditLog } from '../lib/audit.js';

// Append-only mem store: audit must never merge/overwrite earlier rows.
function appendStore() {
  const rows = [];
  return {
    all: () => rows.slice(),
    upsert: (r) => { rows.push(r); return r; },
  };
}

test('record() appends a timestamped, typed event and returns it', () => {
  let t = 1000;
  const store = appendStore();
  const log = createAuditLog({ store, now: () => (t += 1) });
  const rec = log.record('scan.dispatched', { tool: 'nuclei', target: 'app.example.com' }, 'runner');
  assert.equal(rec.type, 'scan.dispatched');
  assert.equal(rec.actor, 'runner');
  assert.deepEqual(rec.detail, { tool: 'nuclei', target: 'app.example.com' });
  assert.equal(typeof rec.id, 'string');
  assert.equal(rec.ts, 1001);
  assert.equal(store.all().length, 1);
});

test('actor defaults to system; every event gets a distinct id', () => {
  const store = appendStore();
  const log = createAuditLog({ store });
  const a = log.record('a');
  const b = log.record('b');
  assert.equal(a.actor, 'system');
  assert.notEqual(a.id, b.id);
  assert.equal(store.all().length, 2);
});

test('append-only — recording never mutates or drops earlier events', () => {
  const store = appendStore();
  const log = createAuditLog({ store });
  log.record('killswitch.engaged', { reason: 'test' }, 'dashboard');
  log.record('killswitch.cleared', {}, 'dashboard');
  const all = log.all();
  assert.equal(all.length, 2);
  assert.equal(all[0].type, 'killswitch.engaged');
  assert.equal(all[1].type, 'killswitch.cleared');
});

test('tail(n) returns the most recent n in order', () => {
  const store = appendStore();
  const log = createAuditLog({ store });
  for (let i = 0; i < 5; i += 1) log.record(`e${i}`);
  const t = log.tail(2);
  assert.equal(t.length, 2);
  assert.equal(t[0].type, 'e3');
  assert.equal(t[1].type, 'e4');
});
