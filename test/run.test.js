import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toRiskPolicy, createRunner, suppressFromAlerts, evidenceForFinding, PASSIVE_TOOLS, aggregatePassive } from '../lib/run.js';

function memStore() {
  const rows = new Map();
  return {
    all: () => [...rows.values()],
    get: (id) => rows.get(id) || null,
    upsert: (r) => (rows.set(r.id, { ...(rows.get(r.id) || {}), ...r }), r),
  };
}

test('safe-only policy denies active and destructive', () => {
  assert.deepEqual(toRiskPolicy({ allowActive: false }), { safe: 'allow', active: 'deny', destructive: 'deny' });
});
test('active-allowed gates active for a human, destructive stays denied', () => {
  assert.deepEqual(toRiskPolicy({ allowActive: true }), { safe: 'allow', active: 'needs_approval', destructive: 'deny' });
});
test('destructive opt-in gates destructive for a human too', () => {
  assert.deepEqual(toRiskPolicy({ allowActive: true, allowDestructive: true }), { safe: 'allow', active: 'needs_approval', destructive: 'needs_approval' });
});

test('evidenceForFinding pulls the salient tool proof (not the banner) for the validator', () => {
  const finding = { host: 'juiceshop', type: 'nuclei', matched: 'params: q (GET)' };
  const sqlmapRaw = [
    '       ___ sqlmap banner legal disclaimer blah blah',
    '[INFO] testing connection to the target URL',
    "GET parameter 'q' is vulnerable",
    'Parameter: q (GET)',
    '    Type: boolean-based blind',
    "    Payload: q=test%' AND 9992=9992",
    'back-end DBMS: SQLite',
  ].join('\n');
  const executed = [
    { ran: true, found: 0, call: { tool: 'httpx', target: 'http://juiceshop:3000' }, rawExcerpt: '200 OK Juice Shop' },
    { ran: true, found: 1, call: { tool: 'sqlmap', target: 'http://juiceshop:3000/rest/products/search?q=test' }, rawExcerpt: sqlmapRaw },
  ];
  const ev = evidenceForFinding(finding, executed);
  assert.match(ev, /vulnerable/i);            // the proof, not "params: q (GET)"
  assert.match(ev, /boolean-based blind/i);
  assert.match(ev, /SQLite/);
  assert.ok(ev.length <= 400 + 120);          // concise enough to survive the validator's clip
  assert.ok(!/legal disclaimer/i.test(ev));   // banner noise dropped
});

test('evidenceForFinding falls back to the finding own evidence when no tool output matches', () => {
  const ev = evidenceForFinding({ host: 'a.example.com', matched: 'reflected <svg>' }, [
    { ran: true, found: 1, call: { tool: 'sqlmap', target: 'http://other.test/x?y=1' }, rawExcerpt: 'vulnerable elsewhere' },
  ]);
  assert.match(ev, /reflected/);
  assert.ok(!/elsewhere/.test(ev)); // different host → not borrowed
});

test('FP filter suppresses weak false positives but never a strong/confirmed finding', () => {
  const fp = { verdict: 'false_positive', reason: 'thin' };
  // weak + flagged → suppressed
  assert.equal(suppressFromAlerts({ severity: 'low', confidence: 30 }, fp), true);
  // confirmed SQLi (high sev, conf 75) flagged FP → MUST NOT be suppressed (the live-run bug)
  assert.equal(suppressFromAlerts({ severity: 'high', confidence: 75 }, fp), false);
  assert.equal(suppressFromAlerts({ severity: 'critical' }, fp), false);
  assert.equal(suppressFromAlerts({ confidence: 70 }, fp), false);
  // not flagged FP → never suppressed regardless of strength
  assert.equal(suppressFromAlerts({ severity: 'low' }, { verdict: 'likely' }), false);
  assert.equal(suppressFromAlerts({ severity: 'low' }, null), false);
});

test('PASSIVE_TOOLS are OSINT-only — no tool that contacts the target', () => {
  const targetContacting = ['httpx', 'dnsx', 'naabu', 'nmap', 'nuclei', 'katana', 'ffuf', 'feroxbuster', 'dalfox', 'sqlmap', 'crlfuzz', 'sstimap', 'commix', 'wpscan', 'gowitness'];
  for (const t of PASSIVE_TOOLS) assert.ok(!targetContacting.includes(t), `${t} contacts the target — not passive`);
  assert.deepEqual(PASSIVE_TOOLS, ['subfinder', 'assetfinder', 'gau', 'waybackurls']);
});

test('aggregatePassive dedupes subdomains + urls and ignores failed/other results', () => {
  const out = aggregatePassive([
    { ok: true, kind: 'subdomains', items: ['a.example.com', 'b.example.com'] },
    { ok: true, kind: 'subdomains', items: ['a.example.com'] },           // dup
    { ok: true, kind: 'urls', items: ['https://a.example.com/x?q=1'] },
    { ok: false, kind: 'urls', items: ['https://nope.example.com'] },     // failed → ignored
    { ok: true, kind: 'findings', items: [{ x: 1 }] },                    // non-recon kind → ignored
  ]);
  assert.deepEqual(out.subdomains, ['a.example.com', 'b.example.com']);
  assert.deepEqual(out.urls, ['https://a.example.com/x?q=1']);
});

test('a passive run only dispatches PASSIVE_TOOLS (never touches the target with active tools)', async () => {
  const dispatched = [];
  // Intercept the agent client by stubbing the brain import is hard; instead assert via a fake runner path:
  const runs = memStore();
  const recon = memStore();
  const runner = createRunner({
    env: { AGENT_URL: 'http://agent.invalid', AGENT_TOKEN: 't' },
    runs, reconStore: recon,
    audit: { record: (type, detail) => { if (type === 'scan.dispatched') dispatched.push(detail.tool); } },
  });
  // agent.invalid is unreachable → scans throw and are swallowed, but dispatch audit still fires first.
  const r = await runner.runPassiveRecon({ name: 'p', scope: { inScope: ['example.com'], outOfScope: [] } });
  assert.equal(typeof r.id, 'string');
  // every dispatched tool must be in the passive allowlist
  for (const t of dispatched) assert.ok(PASSIVE_TOOLS.includes(t), `dispatched non-passive tool: ${t}`);
  assert.ok(dispatched.length > 0);
});

test('an engaged kill-switch halts the run before any scan dispatch', async () => {
  const runs = memStore();
  const events = [];
  const audit = { record: (type) => events.push(type) };
  const killswitch = { engaged: () => true, assert() { throw new Error('kill_switch_engaged'); } };
  const runner = createRunner({
    env: { AGENT_URL: 'http://agent.invalid', AGENT_TOKEN: 't' },
    audit, killswitch, runs, llm: { clients: [], chat: async () => ({}) },
  });
  const r = await runner.runEngagement({ name: 'halt-me', scope: { inScope: [], outOfScope: [] }, policy: {}, evidenceMode: 'light' });
  assert.equal(r.status, 'halted');
  assert.equal(runs.get(r.id).status, 'halted');
  assert.ok(events.includes('run.halted'));
});
