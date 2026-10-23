import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makePlanEnsemble } from '../lib/llm.js';
import { createCriticHook } from '../lib/critic.js';

test('plan ensemble UNIONs steps from both models and dedupes', async () => {
  const c1 = { chat: async () => JSON.stringify({ done: false, steps: [{ tool: 'subfinder', target: 'a.example.com', profile: 'quick' }] }) };
  const c2 = { chat: async () => JSON.stringify({ done: true, steps: [
    { tool: 'httpx', target: 'a.example.com', profile: 'quick' },
    { tool: 'subfinder', target: 'a.example.com', profile: 'quick' }, // dup of c1
  ] }) };
  const chat = makePlanEnsemble([c1, c2]);
  const out = JSON.parse(await chat([{ role: 'user', content: 'x' }]));
  assert.equal(out.steps.length, 2); // subfinder + httpx, dup dropped
  assert.equal(out.done, false);     // not all responders agreed done
});

test('plan ensemble survives one model failing (uses the other)', async () => {
  const good = { chat: async () => JSON.stringify({ done: true, steps: [{ tool: 'httpx', target: 'a.example.com' }] }) };
  const bad = { chat: async () => { throw new Error('rate_limited'); } };
  const chat = makePlanEnsemble([bad, good]);
  const out = JSON.parse(await chat([]));
  assert.equal(out.steps.length, 1);
  assert.equal(out.done, true);
});

test('plan ensemble throws only when ALL models fail', async () => {
  const chat = makePlanEnsemble([{ chat: async () => { throw new Error('x'); } }]);
  await assert.rejects(() => chat([]));
});

test('critic ensemble takes the STRICTEST verdict across models', async () => {
  const allow = { chat: async () => JSON.stringify({ verdicts: [{ i: 0, decision: 'allow' }] }) };
  const deny = { chat: async () => JSON.stringify({ verdicts: [{ i: 0, decision: 'deny', reason: 'oos' }] }) };
  const hook = createCriticHook({ critic: { enabled: true, clients: [allow, deny] }, scope: { inScope: ['example.com'] } });
  const out = await hook([{ decision: 'allow', call: { tool: 'x' } }], { surface: {}, findings: [] });
  assert.equal(out[0].decision, 'deny'); // safest wins
});
