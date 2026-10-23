import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderReport } from '../lib/report.js';

test('renders markdown for a finding including its name', () => {
  const md = renderReport({ name: 'SQL injection', severity: 'high', type: 'sqli', target: 'http://h/s?q=1', matched: 'param q injectable' });
  assert.equal(typeof md, 'string');
  assert.ok(md.length > 0);
  assert.ok(/SQL injection/i.test(md));
});
test('null item → null (no fabrication)', () => {
  assert.equal(renderReport(null), null);
});
test('renders a chain (has steps) without throwing', () => {
  const md = renderReport({ title: 'XSS to ATO', severity: 'critical', steps: [{}, {}], rationale: 'token leak' });
  assert.ok(typeof md === 'string' && md.length > 0);
});
