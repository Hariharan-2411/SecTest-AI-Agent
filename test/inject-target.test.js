import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as brain from '../vendor/brain.mjs';

const { pickInjectionTarget } = brain;

test('picks a param-bearing URL over the root', () => {
  const urls = ['http://h:3000/plain', 'http://h:3000/rest/search?q=1'];
  assert.equal(pickInjectionTarget('h', urls, 'http://h:3000'), 'http://h:3000/rest/search?q=1');
});
test('falls back when no param URL exists for the host', () => {
  assert.equal(pickInjectionTarget('h', ['http://h:3000/plain'], 'http://h:3000'), 'http://h:3000');
});
test('ignores param URLs on a different host', () => {
  assert.equal(pickInjectionTarget('h', ['http://other/a?x=1'], 'http://h:3000'), 'http://h:3000');
});
test('prefers the URL with more parameters', () => {
  const urls = ['http://h/a?x=1', 'http://h/b?x=1&y=2&z=3'];
  assert.equal(pickInjectionTarget('h', urls, 'http://h'), 'http://h/b?x=1&y=2&z=3');
});

test('deterministic injection pass runs sqlmap on a discovered param URL even if the planner proposes nothing', async () => {
  const scope = { inScope: ['h'], outOfScope: [] };
  const chat = async () => JSON.stringify({ done: true, steps: [] }); // planner picks nothing
  const scanned = [];
  const agent = {
    async scan({ tool, target }) {
      scanned.push(`${tool}@${target}`);
      const body = tool === 'sqlmap'
        ? { kind: 'findings', host: 'h', items: [{ templateId: 'sqlmap-sqli', name: 'SQLi', severity: 'high', type: 'sqli', matched: 'q' }], count: 1 }
        : { kind: 'findings', host: 'h', items: [], count: 0 };
      return { status: 200, body };
    },
  };
  const res = await brain.runReconLoop({
    scope, chat, agentClient: agent, approve: async () => true,
    policy: { safe: 'allow', active: 'needs_approval', destructive: 'needs_approval' },
    seeds: ['http://h/search?q=1'],
  });
  assert.ok(scanned.some((s) => s === 'sqlmap@http://h/search?q=1'), 'sqlmap ran on the param URL');
  assert.ok((res.findings || []).length >= 1, 'a finding surfaced from the injection pass');
});
