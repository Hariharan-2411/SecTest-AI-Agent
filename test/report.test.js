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
test('a finding with no steps gets a type-aware PoC scaffold (repro steps + command)', () => {
  const md = renderReport({ name: 'Boolean SQLi', severity: 'high', type: 'sqli-boolean', target: 'http://h/s?q=1', param: 'q', matched: 'response differs' });
  assert.match(md, /boolean/i);   // the type-aware reproduction step
  assert.match(md, /curl/);       // the repro command template
});
test('an unrecognized finding type still gets a generic reproduction step', () => {
  const md = renderReport({ name: 'Odd thing', severity: 'low', type: 'misc', target: 'http://h', matched: 'x' });
  assert.match(md, /Steps To Reproduce/i);
  assert.match(md, /reproduce/i); // generic scaffold line, not the empty placeholder
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
