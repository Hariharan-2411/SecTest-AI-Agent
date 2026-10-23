import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toRiskPolicy } from '../lib/run.js';

test('safe-only policy denies active and destructive', () => {
  assert.deepEqual(toRiskPolicy({ allowActive: false }), { safe: 'allow', active: 'deny', destructive: 'deny' });
});
test('active-allowed gates active for a human, destructive stays denied', () => {
  assert.deepEqual(toRiskPolicy({ allowActive: true }), { safe: 'allow', active: 'needs_approval', destructive: 'deny' });
});
test('destructive opt-in gates destructive for a human too', () => {
  assert.deepEqual(toRiskPolicy({ allowActive: true, allowDestructive: true }), { safe: 'allow', active: 'needs_approval', destructive: 'needs_approval' });
});
