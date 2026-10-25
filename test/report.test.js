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
test('a chain narrative (summary/impact/remediation) is rendered into the report', () => {
  const md = renderReport({
    title: 'IDOR to account takeover',
    severity: 'critical',
    steps: [{ type: 'idor' }, { type: 'auth-bypass' }],
    rationale: 'ids are sequential',
    narrative: {
      source: 'llm',
      summary: 'Sequential object ids let any user read another user’s record.',
      impact: 'An attacker enumerates ids to exfiltrate all customer PII.',
      remediation: 'Enforce per-object authorization server-side.',
      cvss: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
    },
  });
  assert.match(md, /exfiltrate all customer PII/);          // impact prose present
  assert.match(md, /per-object authorization/);             // remediation present
  assert.match(md, /sequential/i);                          // summary present
});
