import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as brain from '../vendor/brain.mjs';

const scope = { inScope: ['*.example.com'], outOfScope: [] };

test('proposeChains is exported and returns the expected shape on empty input', async () => {
  const r = await brain.proposeChains([], { chat: async () => '[]', scope });
  assert.ok(Array.isArray(r.chains));
  assert.ok('source' in r && 'rejected' in r);
});

test('chains span multiple in-scope hosts (cross-asset depth/impact)', async () => {
  const findings = [
    { id: 'f1', type: 'nuclei', host: 'a.example.com', name: 'exposure', severity: 'high' },
    { id: 'f2', type: 'nuclei', host: 'b.example.com', name: 'cve', severity: 'high' },
  ];
  const chat = async () => JSON.stringify({ chains: [
    { title: 'cross-host', steps: [{ findingId: 'f1' }, { findingId: 'f2' }], rationale: 'a→b' },
  ]});
  const r = await brain.proposeChains(findings, { chat, scope });
  assert.ok(r.chains.length >= 1, 'expected at least one cross-host chain');
  assert.ok(r.chains[0].steps.length >= 2, 'chain must have >=2 grounded steps');
});

test('a chain step on an OUT-of-scope host is rejected (scope still gates chaining)', async () => {
  const findings = [
    { id: 'f1', type: 'nuclei', host: 'a.example.com', name: 'x', severity: 'high' },
    { id: 'f2', type: 'nuclei', host: 'evil.notours.com', name: 'y', severity: 'high' },
  ];
  const chat = async () => JSON.stringify({ chains: [
    { title: 'leaks scope', steps: [{ findingId: 'f1' }, { findingId: 'f2' }], rationale: 'nope' },
  ]});
  const r = await brain.proposeChains(findings, { chat, scope });
  // f2 is out of scope → that step can't ground; a <2-step chain is rejected.
  const anyWithOutOfScope = r.chains.some((c) => (c.steps || []).some((s) => /notours/.test(JSON.stringify(s))));
  assert.equal(anyWithOutOfScope, false);
});
