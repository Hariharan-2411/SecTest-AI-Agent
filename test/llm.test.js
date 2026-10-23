import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createLlm, SAFETY_PREAMBLE } from '../lib/llm.js';

test('createLlm selects provider from env and exposes chat/parseChat/clients', () => {
  const llm = createLlm({ LLM_PROVIDER: 'groq', LLM_MODEL: 'm1', LLM_API_KEY: 'k' });
  assert.ok(llm.provider.startsWith('groq')); // composite "groq:m1" for the ensemble
  assert.equal(typeof llm.chat, 'function');
  assert.equal(typeof llm.parseChat, 'function');
  assert.ok(Array.isArray(llm.clients) && llm.clients.length >= 1);
});

test('createLlm with a second model exposes both clients (ensemble members)', () => {
  const llm = createLlm({ LLM_PROVIDER: 'groq', LLM_MODEL: 'm1', LLM_API_KEY: 'k',
    LLM_FALLBACK_PROVIDER: 'openai-compatible', LLM_FALLBACK_BASE_URL: 'http://x/v1', LLM_FALLBACK_MODEL: 'm2', LLM_FALLBACK_API_KEY: 'k2' });
  assert.equal(llm.clients.length, 2);
});

test('safety preamble is non-empty and bans destructive actions', () => {
  assert.ok(/non-destructive/i.test(SAFETY_PREAMBLE));
  assert.ok(/never auto-submit/i.test(SAFETY_PREAMBLE));
});

test('openai-compatible requires a base url', async () => {
  const llm = createLlm({ LLM_PROVIDER: 'openai-compatible', LLM_BASE_URL: '' });
  await assert.rejects(() => llm.chat([{ role: 'user', content: 'hi' }]), /no base url/);
});
