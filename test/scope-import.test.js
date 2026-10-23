import { test } from 'node:test';
import assert from 'node:assert/strict';
import { importScope } from '../lib/scopeImport.js';

test('HackerOne structured_scopes JSON → in/out split, eligibility respected', () => {
  const input = JSON.stringify({
    data: [
      { type: 'structured-scope', attributes: { asset_type: 'URL', asset_identifier: 'api.example.com', eligible_for_submission: true } },
      { type: 'structured-scope', attributes: { asset_type: 'WILDCARD', asset_identifier: '*.example.com', eligible_for_submission: true } },
      { type: 'structured-scope', attributes: { asset_type: 'URL', asset_identifier: 'legacy.example.com', eligible_for_submission: false } },
      { type: 'structured-scope', attributes: { asset_type: 'GOOGLE_PLAY_APP_ID', asset_identifier: 'com.example.app', eligible_for_submission: true } },
    ],
  });
  const r = importScope(input);
  assert.equal(r.source, 'hackerone');
  assert.deepEqual(r.urls.sort(), ['api.example.com', 'example.com']);        // wildcard → bare host + flag
  assert.deepEqual(r.outOfScopeUrls, ['legacy.example.com']);                  // eligible_for_submission:false
  assert.equal(r.enumerateSubdomains, true);                                   // a wildcard was in scope
  assert.equal(r.skipped.length, 1);                                           // the Google Play app id
  assert.match(r.skipped[0].identifier, /com\.example\.app/);
});

test('Bugcrowd in_scope/out_of_scope JSON (objects with target+category)', () => {
  const input = JSON.stringify({
    in_scope: [ { target: '*.example.com', type: 'website' }, { target: 'https://app.example.com', type: 'api' } ],
    out_of_scope: [ { target: 'support.example.com' } ],
  });
  const r = importScope(input);
  assert.equal(r.source, 'bugcrowd');
  assert.ok(r.urls.includes('example.com'));
  assert.ok(r.urls.includes('https://app.example.com'));
  assert.deepEqual(r.outOfScopeUrls, ['support.example.com']);
  assert.equal(r.enumerateSubdomains, true);
});

test('plain text with In scope / Out of scope headers and markdown bullets', () => {
  const input = [
    'In scope:',
    '- `app.example.com`',
    '* https://api.example.com/v1',
    '',
    'Out of scope',
    '- admin.example.com — internal only',
  ].join('\n');
  const r = importScope(input);
  assert.equal(r.source, 'text');
  assert.ok(r.urls.includes('app.example.com'));
  assert.ok(r.urls.includes('https://api.example.com/v1'));
  assert.deepEqual(r.outOfScopeUrls, ['admin.example.com']);
});

test('a bare list of domains is all in-scope; junk lines are ignored', () => {
  const r = importScope('example.com\nfoo.example.org\nthis line has no host at all');
  assert.deepEqual(r.urls.sort(), ['example.com', 'foo.example.org']);
  assert.equal(r.outOfScopeUrls.length, 0);
  assert.equal(r.enumerateSubdomains, false);
});

test('empty / hostless input yields no targets and a warning (fail-closed)', () => {
  const r = importScope('   \n\n');
  assert.equal(r.urls.length, 0);
  assert.ok(r.warnings.some((w) => /no .*scope/i.test(w)));
});
