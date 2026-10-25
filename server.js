// Iris Orchestrator — standalone HTTP service: intake, dashboard, remote approval.
// Drives the companion agent headlessly. Scope is enforced server-side by the
// agent on every /scan; this process adds intake, the approval broker, and the
// bot/dashboard. No auto-submit.
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as brain from './vendor/brain.mjs';
import { collection } from './lib/store.js';
import { createEventBus } from './lib/events.js';
import { createAuditLog } from './lib/audit.js';
import { createKillSwitch } from './lib/killswitch.js';
import { createApprovalBroker } from './lib/approvals.js';
import { createLlm, createCritic } from './lib/llm.js';
import { createBot } from './lib/bot.js';
import { createRunner } from './lib/run.js';
import { createMonitor } from './lib/monitor.js';
import { buildEngagement } from './lib/intake.js';
import { importScope } from './lib/scopeImport.js';
import { renderReport } from './lib/report.js';

const env = process.env;
const PORT = Number(env.PORT || 8790);
const DASH_TOKEN = env.DASHBOARD_TOKEN || '';
const here = dirname(fileURLToPath(import.meta.url));

const approvalsStore = collection('approvals');
const runsStore = collection('runs');
const findingsStore = collection('findings');
const chainsStore = collection('chains');
const fingerprintsStore = collection('fingerprints');
const evidenceStore = collection('evidence');
const auditStore = collection('audit');
const killswitchStore = collection('killswitch');

const bus = createEventBus();
const audit = createAuditLog({ store: auditStore, emit: (rec) => bus.emit({ kind: 'audit', ...rec }) });
const killswitch = createKillSwitch({ store: killswitchStore, audit });
const broker = createApprovalBroker({
  store: approvalsStore,
  notify: (rec) => bot.notifyApproval(rec),
  audit,
  timeoutMs: Number(env.APPROVAL_TIMEOUT_MS || 30 * 60 * 1000),
});
const llm = createLlm(env);
const critic = createCritic(env);
const bot = createBot({ env, broker });
const runner = createRunner({ env, broker, llm, critic, bot, audit, killswitch, runs: runsStore, findingsStore, chainsStore, fingerprintsStore, evidenceStore });
const monitorsStore = collection('monitors');
const monitor = createMonitor({ runner, store: monitorsStore, audit, killswitch, bot });

function json(res, code, body) {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}
function readBody(req) {
  return new Promise((r) => { let d = ''; req.on('data', (c) => (d += c)); req.on('end', () => { try { r(d ? JSON.parse(d) : {}); } catch { r({}); } }); });
}
function authed(req, url) {
  if (!DASH_TOKEN) return true; // no token configured → open (dev)
  // Header for fetch(); query param for EventSource (which can't set headers).
  if ((req.headers['x-dashboard-token'] || '') === DASH_TOKEN) return true;
  return url && url.searchParams.get('token') === DASH_TOKEN;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const path = url.pathname;

  if (path === '/health' && req.method === 'GET') {
    return json(res, 200, { ok: true, bot: bot.enabled, agent: env.AGENT_URL, llm: llm.provider, critic: critic.enabled ? critic.provider : false });
  }
  if (path === '/' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end(readFileSync(resolve(here, 'web/index.html'), 'utf8'));
  }

  // --- API (token-gated) ---
  if (path.startsWith('/api/')) {
    if (!authed(req, url)) return json(res, 401, { error: 'unauthorized' });

    // Live update stream — one nudge per audit event; the client re-pulls on each.
    if (path === '/api/events' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
      res.write('retry: 3000\n\n');
      const unsub = bus.subscribe((e) => { try { res.write(`data: ${JSON.stringify(e)}\n\n`); } catch (_) {} });
      const hb = setInterval(() => { try { res.write(': hb\n\n'); } catch (_) {} }, 25000);
      if (typeof hb.unref === 'function') hb.unref();
      req.on('close', () => { clearInterval(hb); unsub(); });
      return; // keep the connection open
    }

    if (path === '/api/killswitch' && req.method === 'GET') return json(res, 200, killswitch.state());
    if (path === '/api/killswitch' && req.method === 'POST') {
      const body = await readBody(req);
      if (body.action === 'engage') {
        const st = killswitch.engage(body.reason || '', 'dashboard');
        const denied = broker.denyAll('killswitch'); // release any suspended runs, fail-safe
        return json(res, 200, { ...st, deniedPending: denied });
      }
      if (body.action === 'clear') return json(res, 200, killswitch.clear('dashboard'));
      return json(res, 400, { error: 'action must be engage|clear' });
    }

    if (path === '/api/engagements' && req.method === 'POST') {
      if (killswitch.engaged()) return json(res, 503, { error: 'kill_switch_engaged' });
      const body = await readBody(req);
      let engagement;
      try {
        engagement = buildEngagement(body, { hostFromUrl: brain.hostFromUrl, parseScopeText: brain.parseScopeText });
      } catch (e) { return json(res, 400, { error: String(e) }); }
      audit.record('engagement.created', { name: engagement.name, scope: engagement.scope, evidenceMode: engagement.evidenceMode }, 'intake');
      // Kick the run; don't block the HTTP response on the whole loop.
      runner.runEngagement(engagement).catch(() => {});
      return json(res, 202, { accepted: true, engagement });
    }
    if (path === '/api/audit' && req.method === 'GET') {
      const n = Number(url.searchParams.get('tail') || 0);
      return json(res, 200, n > 0 ? audit.tail(n) : audit.all());
    }

    if (path === '/api/scope/import' && req.method === 'POST') {
      const body = await readBody(req);
      return json(res, 200, importScope(body.text != null ? body.text : body));
    }

    if (path === '/api/monitors' && req.method === 'GET') return json(res, 200, monitor.list());
    if (path === '/api/monitors' && req.method === 'POST') {
      if (killswitch.engaged()) return json(res, 503, { error: 'kill_switch_engaged' });
      const body = await readBody(req);
      let engagement;
      try {
        engagement = buildEngagement(body, { hostFromUrl: brain.hostFromUrl, parseScopeText: brain.parseScopeText });
      } catch (e) { return json(res, 400, { error: String(e) }); }
      const interval = Math.max(Number(body.intervalMs || 6 * 60 * 60 * 1000), 60 * 1000); // floor 60s
      const mon = monitor.schedule(engagement, interval);
      if (body.runNow !== false) monitor.runCycle(mon.id).catch(() => {}); // kick an immediate baseline cycle
      return json(res, 201, mon);
    }
    const mStop = path.match(/^\/api\/monitors\/([^/]+)\/stop$/);
    if (mStop && req.method === 'POST') return json(res, 200, { ok: monitor.stop(mStop[1]) });
    if (path === '/api/approvals' && req.method === 'GET') return json(res, 200, broker.list());
    const m = path.match(/^\/api\/approvals\/([^/]+)\/(approve|deny)$/);
    if (m && req.method === 'POST') {
      const ok = m[2] === 'approve' ? broker.approve(m[1], 'dashboard') : broker.deny(m[1], 'dashboard');
      return json(res, ok ? 200 : 409, { ok });
    }
    if (path === '/api/runs' && req.method === 'GET') return json(res, 200, runsStore.all());
    if (path === '/api/findings' && req.method === 'GET') return json(res, 200, findingsStore.all());
    if (path === '/api/chains' && req.method === 'GET') return json(res, 200, chainsStore.all());
    const mRep = path.match(/^\/api\/report\/(.+)$/);
    if (mRep && req.method === 'GET') {
      const id = decodeURIComponent(mRep[1]);
      const item = findingsStore.get(id) || chainsStore.get(id);
      if (!item) return json(res, 404, { error: 'not_found' });
      return json(res, 200, { id, markdown: renderReport(item) });
    }
    const mEv = path.match(/^\/api\/findings\/(.+)\/evidence$/);
    if (mEv && req.method === 'GET') {
      const f = findingsStore.get(decodeURIComponent(mEv[1]));
      if (!f) return json(res, 404, { error: 'not_found' });
      const ev = evidenceStore.get(f.runId);
      return json(res, 200, { findingId: f.id, runId: f.runId, evidence: (ev && ev.items) || [] });
    }
    return json(res, 404, { error: 'not_found' });
  }
  json(res, 404, { error: 'not_found' });
});

server.listen(PORT, () => {
  console.log(`Iris Orchestrator on :${PORT}  (agent=${env.AGENT_URL}  llm=${llm.provider}  telegram=${bot.enabled.telegram})`);
  bot.startPolling().catch(() => {});
  monitor.resume(); // re-arm any monitors that were active before a restart
  if (killswitch.engaged()) console.warn('⚠ kill-switch is ENGAGED — runs are halted until cleared via POST /api/killswitch');
});
