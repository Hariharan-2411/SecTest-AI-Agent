import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createBot } from '../lib/bot.js';

// Capture outbound webhook posts without touching the network.
function fakeFetch() {
  const calls = [];
  const fn = async (url, opts) => { calls.push({ url, body: JSON.parse(opts.body) }); return { json: async () => ({}) }; };
  fn.calls = calls;
  return fn;
}

test('a Slack webhook gets a one-way finding alert with {text}', async () => {
  const fetchImpl = fakeFetch();
  const bot = createBot({ env: { SLACK_WEBHOOK_URL: 'https://hooks.slack.test/x' }, fetchImpl });
  assert.equal(bot.enabled.slack, true);
  await bot.notifyFinding({ severity: 'high', title: 'SQLi', target: 'app.example.com' });
  const slack = fetchImpl.calls.find((c) => c.url.includes('slack.test'));
  assert.ok(slack, 'posted to slack');
  assert.match(slack.body.text, /high/);
  assert.match(slack.body.text, /SQLi/);
});

test('Slack also gets a one-way notice when an approval is needed', async () => {
  const fetchImpl = fakeFetch();
  const bot = createBot({ env: { SLACK_WEBHOOK_URL: 'https://hooks.slack.test/x' }, fetchImpl });
  await bot.notifyApproval({ id: 'apr_1', risk: 'active', call: { tool: 'nuclei', target: 'app.example.com' } });
  const slack = fetchImpl.calls.find((c) => c.url.includes('slack.test'));
  assert.ok(slack);
  assert.match(slack.body.text, /nuclei/);
  assert.match(slack.body.text, /apr_1/);
});

test('with nothing configured, notifiers no-op (no posts, enabled all false)', async () => {
  const fetchImpl = fakeFetch();
  const bot = createBot({ env: {}, fetchImpl });
  assert.deepEqual(bot.enabled, { telegram: false, discord: false, slack: false });
  await bot.notifyFinding({ title: 'x' });
  assert.equal(fetchImpl.calls.length, 0);
});
