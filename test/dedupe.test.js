import { test } from 'node:test';
import assert from 'node:assert/strict';
import { markSeen, fingerprint } from '../lib/dedupe.js';

function memStore() {
  const m = new Map();
  return { all: () => [...m.values()], get: (id, k = 'id') => m.get(id) || null, upsert: (r, k = 'id') => (m.set(r[k], { ...(m.get(r[k]) || {}), ...r }), r) };
}

test('fingerprint ignores the run-scoped id (stable across runs)', () => {
  const a = { id: 'r1:x', type: 'sqli', name: 'SQLi', host: 'h' };
  const b = { id: 'r2:y', type: 'sqli', name: 'SQLi', host: 'h' };
  assert.equal(fingerprint(a), fingerprint(b));
});

test('first sighting is new, repeat is seen, and nothing is dropped', () => {
  const store = memStore();
  const F = { id: 'r1:1', type: 'sqli', name: 'SQLi', host: 'h' };
  const out1 = markSeen([F], { store, runId: 'r1' });
  assert.equal(out1.length, 1);
  assert.equal(out1[0].status, 'new');

  const F2 = { id: 'r2:9', type: 'sqli', name: 'SQLi', host: 'h' }; // same bug, new run
  const G = { id: 'r2:10', type: 'xss', name: 'XSS', host: 'h' };   // brand new
  const out2 = markSeen([F2, G], { store, runId: 'r2' });
  assert.equal(out2.length, 2);                 // never drops
  assert.equal(out2.find(x => x.type === 'sqli').status, 'seen');
  assert.equal(out2.find(x => x.type === 'sqli').firstRun, 'r1');
  assert.equal(out2.find(x => x.type === 'xss').status, 'new');
});
