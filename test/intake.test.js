import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildEngagement, scanRules } from '../lib/intake.js';

// Minimal fakes matching the brain's scope helpers.
const hostFromUrl = (u) => { try { return new URL(u).hostname.toLowerCase(); } catch { return ''; } };
const parseScopeText = (t) => String(t).split(/\n+/).map((s) => s.trim()).filter(Boolean);
const helpers = { hostFromUrl, parseScopeText };

test('derives hosts + wildcards when enumerating subdomains', () => {
  const e = buildEngagement({ urls: ['https://app.example.com/x'], enumerateSubdomains: true, confirmed: true, rulesText: 'automation allowed' }, helpers);
  assert.deepEqual(e.scope.inScope.sort(), ['*.app.example.com', 'app.example.com']);
});

test('fail-closed: unconfirmed → safe only', () => {
  const e = buildEngagement({ urls: ['https://a.example.com'], rulesText: 'automation allowed', confirmed: false }, helpers);
  assert.equal(e.policy.allowActive, false);
  assert.equal(e.policy.maxRisk, 'safe');
});

test('rateMax flows into policy (0 default, clamped to >=0)', () => {
  assert.equal(buildEngagement({ urls: ['https://a.example.com'] }, helpers).policy.rateMax, 0);
  assert.equal(buildEngagement({ urls: ['https://a.example.com'], rateMax: 5 }, helpers).policy.rateMax, 5);
  assert.equal(buildEngagement({ urls: ['https://a.example.com'], rateMax: -3 }, helpers).policy.rateMax, 0);
});

test('passive flag → mode "passive" (default is "full")', () => {
  const p = buildEngagement({ urls: ['https://a.example.com'], passive: true }, helpers);
  assert.equal(p.mode, 'passive');
  assert.ok(p.warnings.some((w) => /passive/i.test(w)));
  const f = buildEngagement({ urls: ['https://a.example.com'] }, helpers);
  assert.equal(f.mode, 'full');
});

test('fail-closed: confirmed but rules forbid automation → safe only', () => {
  const e = buildEngagement({ urls: ['https://a.example.com'], rulesText: 'No automated scanning. Manual only.', confirmed: true }, helpers);
  assert.equal(e.policy.allowActive, false);
  assert.ok(e.warnings.some((w) => /forbid automation/.test(w)));
});

test('confirmed + rules permit → active enabled, destructive still off without opt-in', () => {
  const e = buildEngagement({ urls: ['https://a.example.com'], rulesText: 'Automated scanning is allowed.', confirmed: true }, helpers);
  assert.equal(e.policy.allowActive, true);
  assert.equal(e.policy.allowDestructive, false);
  assert.equal(e.policy.maxRisk, 'active');
});

test('destructive requires explicit opt-in on top of active', () => {
  const e = buildEngagement({ urls: ['https://a.example.com'], rulesText: 'automated testing permitted', confirmed: true, allowDestructive: true }, helpers);
  assert.equal(e.policy.allowDestructive, true);
  assert.equal(e.policy.maxRisk, 'destructive');
});

test('scanRules finds deny/allow phrases', () => {
  assert.ok(scanRules('No fuzzing please').denies.length);
  assert.ok(scanRules('scanners allowed').allows.length);
});

test('evidenceMode defaults to light, preserves full, rejects bogus', () => {
  const base = { urls: ['https://a.example.com'] };
  assert.equal(buildEngagement(base, helpers).evidenceMode, 'light');
  assert.equal(buildEngagement({ ...base, evidenceMode: 'full' }, helpers).evidenceMode, 'full');
  assert.equal(buildEngagement({ ...base, evidenceMode: 'bogus' }, helpers).evidenceMode, 'light');
});
