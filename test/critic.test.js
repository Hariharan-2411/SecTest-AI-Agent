import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as brain from '../vendor/brain.mjs';
import { createCriticHook, buildCriticPrompt } from '../lib/critic.js';

const { stricterDecision, runReconLoop } = brain;

test('stricterDecision: critic can only tighten, never loosen', () => {
  assert.equal(stricterDecision('allow', 'deny'), 'deny');
  assert.equal(stricterDecision('allow', 'needs_approval'), 'needs_approval');
  assert.equal(stricterDecision('deny', 'allow'), 'deny');            // cannot loosen
  assert.equal(stricterDecision('needs_approval', 'allow'), 'needs_approval');
  assert.equal(stricterDecision('allow', undefined), 'allow');        // missing verdict
  assert.equal(stricterDecision('allow', 'garbage'), 'allow');        // unknown verdict
  assert.equal(stricterDecision('needs_approval', 'deny'), 'deny');
});

test('createCriticHook returns null when no critic configured', () => {
  assert.equal(createCriticHook({ critic: null }), null);
  assert.equal(createCriticHook({ critic: { enabled: false, chat: () => {} } }), null);
});

test('critic hook maps verdicts back to step order', async () => {
  const critic = {
    enabled: true,
    chat: async () => JSON.stringify({ verdicts: [{ i: 1, decision: 'deny', reason: 'oos' }, { i: 0, decision: 'allow' }] }),
  };
  const hook = createCriticHook({ critic, scope: { inScope: ['example.com'] } });
  const steps = [{ decision: 'allow', call: { tool: 'httpx' } }, { decision: 'allow', call: { tool: 'nuclei' } }];
  const out = await hook(steps, { surface: {}, findings: [] });
  assert.equal(out[0].decision, 'allow');
  assert.equal(out[1].decision, 'deny');
});

test('critic hook throws on unparseable reply (brain then keeps planner decisions)', async () => {
  const critic = { enabled: true, chat: async () => 'not json at all' };
  const hook = createCriticHook({ critic, scope: { inScope: ['example.com'] } });
  await assert.rejects(() => hook([{ decision: 'allow', call: {} }], { surface: {} }));
});

// --- integration through the real loop ---
const scope = { inScope: ['*.example.com'], outOfScope: [] };
const planOf = (steps) => async () => JSON.stringify({ done: true, steps });
const okAgent = { async scan() { return { status: 200, body: { kind: 'subdomains', items: [], count: 0 } }; } };

test('critic DENY stops an otherwise-allowed safe step', async () => {
  let scanned = 0;
  const agent = { async scan() { scanned++; return { status: 200, body: { kind: 'subdomains', items: [], count: 0 } }; } };
  const res = await runReconLoop({
    scope, agentClient: agent, budget: 3,
    chat: planOf([{ tool: 'subfinder', target: 'app.example.com', profile: 'quick' }]),
    critique: async (steps) => steps.map(() => ({ decision: 'deny', reason: 'critic-nope' })),
  });
  assert.equal(scanned, 0);
  assert.ok(res.executed.some((e) => e.decision === 'deny'));
});

test('critic CANNOT loosen a needs_approval step to allow', async () => {
  const seen = [];
  await runReconLoop({
    scope, agentClient: okAgent, budget: 3,
    chat: planOf([{ tool: 'nuclei', target: 'app.example.com', profile: 'quick' }]), // active → needs_approval
    policy: { safe: 'allow', active: 'needs_approval', destructive: 'deny' },
    approve: async (call) => { seen.push(call.tool); return false; },
    critique: async (steps) => steps.map(() => ({ decision: 'allow' })), // tries to loosen
  });
  assert.deepEqual(seen, ['nuclei']); // still routed through human approval, not auto-run
});
