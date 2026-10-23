import { test } from 'node:test';
import assert from 'node:assert/strict';
import { lightEvidence, mask, collectEvidence } from '../lib/evidence.js';

test('mask hides secret-looking tokens', () => {
  assert.ok(!mask('key gsk_ABCDEFGHIJ1234567890 end').includes('gsk_ABCDEFGHIJ1234567890'));
  assert.ok(/\*\*\*/.test(mask('aws AKIAABCDEFGH12345678 x')));
  assert.ok(/\*\*\*/.test(mask('bearer sk-abcdefghijkl1234567890 x')));
});

test('lightEvidence keeps command + bounded masked excerpt', () => {
  const ev = lightEvidence({ call: { tool: 'sqlmap', target: 'http://h/s?q=1' }, command: 'sqlmap -u http://h/s?q=1', rawExcerpt: 'leak gsk_SECRETSECRET1234567890 ' + 'x'.repeat(5000) }, { maxBytes: 100 });
  assert.equal(ev.tool, 'sqlmap');
  assert.ok(ev.excerpt.length <= 100);
  assert.ok(!ev.excerpt.includes('gsk_SECRETSECRET1234567890'));
});

test('collectEvidence only includes steps that ran', () => {
  const ev = collectEvidence([{ ran: true, call: { tool: 'nuclei' }, command: 'nuclei', rawExcerpt: 'x' }, { ran: false, call: { tool: 'ffuf' } }]);
  assert.equal(ev.length, 1);
  assert.equal(ev[0].tool, 'nuclei');
});
