import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createMemory, scopeKey } from '../lib/memory.js';

function docStore() {
  const rows = new Map();
  return {
    all: () => [...rows.values()],
    get: (id) => rows.get(id) || null,
    upsert: (r) => (rows.set(r.id, { ...(rows.get(r.id) || {}), ...r }), r),
  };
}

const engagement = { name: 'e1', scope: { inScope: ['b.example.com', 'a.example.com'], outOfScope: [] } };

test('scopeKey is stable regardless of in-scope ordering', () => {
  assert.equal(
    scopeKey({ scope: { inScope: ['a.example.com', 'b.example.com'] } }),
    scopeKey({ scope: { inScope: ['b.example.com', 'a.example.com'] } })
  );
});

test('first recall is empty (cold); record then recall returns learned state', () => {
  const store = docStore();
  const mem = createMemory({ store });
  assert.deepEqual(mem.recall(engagement), { knownAssets: [], paidOff: [] });

  mem.record(engagement, {
    surface: { hosts: ['a.example.com'], subdomains: ['api.a.example.com'], urls: ['https://a.example.com/x'] },
    executed: [
      { ran: true, found: 2, call: { tool: 'sqlmap' } },
      { ran: true, found: 0, call: { tool: 'httpx' } }, // found nothing → not "paid off"
      { ran: true, found: 1, call: { tool: 'sqlmap' } }, // same tool again → count accumulates
    ],
  });

  const r = mem.recall(engagement);
  assert.ok(r.knownAssets.includes('api.a.example.com'));
  assert.ok(r.knownAssets.includes('https://a.example.com/x'));
  const sqlmap = r.paidOff.find((p) => p.tool === 'sqlmap');
  assert.equal(sqlmap.count, 2);                 // two productive sqlmap runs
  assert.ok(!r.paidOff.some((p) => p.tool === 'httpx')); // httpx found nothing
});

test('record accumulates across runs and dedupes assets', () => {
  const store = docStore();
  const mem = createMemory({ store });
  mem.record(engagement, { surface: { subdomains: ['x.example.com'] }, executed: [{ ran: true, found: 1, call: { tool: 'nuclei' } }] });
  mem.record(engagement, { surface: { subdomains: ['x.example.com', 'y.example.com'] }, executed: [{ ran: true, found: 1, call: { tool: 'nuclei' } }] });
  const r = mem.recall(engagement);
  assert.equal(r.knownAssets.filter((a) => a === 'x.example.com').length, 1); // deduped
  assert.ok(r.knownAssets.includes('y.example.com'));
  assert.equal(r.paidOff.find((p) => p.tool === 'nuclei').count, 2);
  // paidOff is sorted strongest-first
  assert.equal(r.paidOff[0].tool, 'nuclei');
});

test('never throws on garbage', () => {
  const mem = createMemory({ store: docStore() });
  assert.doesNotThrow(() => mem.record(null, null));
  assert.doesNotThrow(() => mem.recall(null));
});
