// Orchestration — wires the engagement through the bundled brain's bounded
// recon loop. Safe tools auto-run; active/destructive steps go through the
// approval broker (remote Approve/Deny). Never auto-submits; results are a
// ranked triage draft for a human.
import * as brain from '../vendor/brain.mjs';
import { createCriticHook } from './critic.js';
import { markSeen, fingerprint } from './dedupe.js';
import { collectEvidence } from './evidence.js';
import { makePlanEnsemble } from './llm.js';

// intake policy → the brain's RISK_POLICY shape (safe|active|destructive →
// allow|needs_approval|deny). active/destructive only ever reach a human-gated
// 'needs_approval' when the engagement policy permits them; otherwise 'deny'.
// Build the evidence the FP validator should judge on: the SALIENT proof lines
// from the tool run that actually produced this finding (e.g. sqlmap's "parameter
// 'q' is vulnerable / Type: boolean-based blind / DBMS: SQLite"), not the thin
// finding field ("params: q (GET)") and not the raw tool banner. Matched to the
// finding by host + a productive (found>0) tool run. Pure.
const EVIDENCE_SIGNAL = /(vulnerab|injectab|injection point|parameter:|\btype:|payload:|back-end dbms|reflected|confirmed|identified the following|200 ok)/i;
export function evidenceForFinding(finding = {}, executed = []) {
  const own = String(finding.matched || finding.evidence || '').trim();
  const host = String(finding.host || finding.target || '');
  const cands = (Array.isArray(executed) ? executed : []).filter(
    (e) => e && e.ran && (e.found || 0) > 0 && typeof e.rawExcerpt === 'string' && e.rawExcerpt &&
      (!host || String((e.call && e.call.target) || '').includes(host))
  );
  cands.sort((a, b) => b.rawExcerpt.length - a.rawExcerpt.length);
  const best = cands[0];
  let tool = '';
  if (best) {
    const lines = best.rawExcerpt.split(/\r?\n|\\n/).map((l) => l.trim()).filter(Boolean);
    const signal = lines.filter((l) => EVIDENCE_SIGNAL.test(l)).slice(0, 8);
    tool = (signal.length ? signal : lines.slice(0, 4)).join('\n');
  }
  // Proof first (it survives the validator's clip), then the finding's own note.
  return [tool, own].filter(Boolean).join('\n---\n').slice(0, 480);
}

// Whether the AI false-positive filter may suppress this finding's ALERT. It may
// only quiet genuinely WEAK findings — never a strongly-corroborated one
// (high/critical severity, or confidence ≥ 70, e.g. a tool-confirmed hit). Hiding
// a real bug is worse than the noise the filter removes.
export function suppressFromAlerts(finding = {}, validation = null) {
  if (!validation || validation.verdict !== 'false_positive') return false;
  const strong = /high|critical/i.test(finding.severity || '') || (Number(finding.confidence) || 0) >= 70;
  return !strong;
}

export function toRiskPolicy(policy = {}) {
  return {
    safe: 'allow',
    active: policy.allowActive ? 'needs_approval' : 'deny',
    destructive: policy.allowDestructive ? 'needs_approval' : 'deny',
  };
}

async function pushScope(env, scope) {
  const res = await fetch(`${env.AGENT_URL}/scope`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'x-agent-token': env.AGENT_TOKEN || '' },
    body: JSON.stringify(scope),
  });
  if (!res.ok) throw new Error(`scope_push_${res.status}`);
  return res.json().catch(() => ({}));
}

export function createRunner({ env = process.env, broker, llm, critic, bot, audit = null, killswitch = null, memory = null, runs, findingsStore, chainsStore, fingerprintsStore, evidenceStore } = {}) {
  async function runEngagement(engagement, opts = {}) {
    const baseClient = brain.makeAgentClient({
      baseUrl: env.AGENT_URL,
      token: env.AGENT_TOKEN,
      evidence: engagement.evidenceMode, // 'light' | 'full' per engagement
    });
    // Wrap scan so every dispatch is auditable and the kill-switch can halt the
    // loop in-flight (a halted scan throws, which the brain treats as a failed step).
    const agentClient = {
      ...baseClient,
      scan: async (call) => {
        killswitch?.assert?.();
        audit?.record('scan.dispatched', { tool: call?.tool, target: call?.target, profile: call?.profile }, 'runner');
        return baseClient.scan(call);
      },
    };
    const id = `run_${Date.now().toString(36)}`;
    const started = Date.now();
    // Kill-switch: refuse to even start a run while halted.
    if (killswitch?.engaged?.()) {
      runs?.upsert({ id, name: engagement.name, status: 'halted', startedAt: started, reason: 'kill_switch_engaged' });
      audit?.record('run.halted', { name: engagement.name, reason: 'kill_switch_engaged' }, 'killswitch');
      return { id, status: 'halted', findings: [], triage: [], ranked: [] };
    }
    runs?.upsert({ id, name: engagement.name, status: 'running', startedAt: started, scope: engagement.scope, policy: engagement.policy });

    // Server-side scope is the real gate; push it so the agent rejects anything
    // off-scope even if the loop asks. Non-fatal if the agent is unreachable at
    // push time — every /scan is still re-checked server-side.
    try { await pushScope(env, engagement.scope); } catch (e) { /* logged in run record */ }

    // Base recon budget, optionally scaled by a monitor's adaptive effort factor.
    const baseBudget = Number(env.RECON_BUDGET || 12);
    const factor = Number(opts.budgetFactor) > 0 ? Number(opts.budgetFactor) : 1;
    const budget = Math.max(1, Math.round(baseBudget * factor));

    // Cross-run memory: start warm — recall known assets (as extra seeds) and the
    // tools that paid off here before (handed to the planner). First run → empty.
    const mem = memory ? memory.recall(engagement) : { knownAssets: [], paidOff: [] };
    const warmUrls = (mem.knownAssets || []).filter((a) => /^https?:\/\//i.test(a));
    const seeds = [...new Set([...(engagement.seeds || []), ...warmUrls])];

    let result;
    try {
      result = await brain.runReconLoop({
        scope: engagement.scope,
        chat: makePlanEnsemble(llm.clients),  // both models propose → union of steps
        agentClient,
        approve: (call) => broker.request(call),
        policy: toRiskPolicy(engagement.policy),
        budget,
        seeds,
        memory: mem,
        // Dual-model: second opinion that can only tighten decisions. null → off.
        critique: createCriticHook({ critic, scope: engagement.scope }),
      });
    } catch (e) {
      runs?.upsert({ id, status: 'error', error: String(e), finishedAt: Date.now() });
      audit?.record('run.error', { id, name: engagement.name, error: String(e) }, 'runner');
      throw e;
    }

    // AI false-positive filter on the findings we'd alert on. RETAIN-ALL: we only
    // compute a verdict here; nothing is dropped. It quiets alerts on likely FPs
    // while every finding is still stored (lows chain into highs).
    const valByFp = new Map();
    for (const f of result.reportworthy || []) {
      try {
        // Judge on the real tool proof, not the thin finding field.
        const enriched = { ...f, matched: evidenceForFinding(f, result.executed) };
        valByFp.set(fingerprint(f), await brain.validateFinding(enriched, { chat: llm.chat }));
      } catch (_) {}
    }

    // Cross-run dedupe: tag new/seen, merge, never drop.
    const ranked = markSeen(result.triage || [], { store: fingerprintsStore, runId: id });
    for (const f of ranked) {
      const v = valByFp.get(fingerprint(f));
      findingsStore?.upsert({ id: `${id}:${f.id || f.fingerprint || Math.random().toString(36).slice(2)}`, runId: id, ...f, ...(v ? { validation: v } : {}) });
    }
    for (const f of ranked.filter((x) => x.status === 'new')) {
      audit?.record('finding.new', { name: f.name || f.title, type: f.type || f.templateId, host: f.host || f.target, severity: f.severity }, 'runner');
    }
    // Alert only on findings NEW this run AND not flagged a false positive — on a
    // monitored re-run, already-seen findings stay quiet, so a ping always means
    // something new and credible.
    const newKeys = new Set(ranked.filter((x) => x.status === 'new').map(fingerprint));
    for (const f of result.reportworthy || []) {
      const v = valByFp.get(fingerprint(f));
      if (suppressFromAlerts(f, v)) {
        audit?.record('finding.suppressed', { name: f.name || f.title, host: f.host || f.target, reason: v.reason }, 'validator');
        continue; // suppressed from alerts, still stored above
      }
      if (!newKeys.has(fingerprint(f))) continue;
      try { await bot?.notifyFinding(f); } catch (_) {}
    }
    // PoC evidence (Light): per-run tool commands + masked output excerpts.
    evidenceStore?.upsert({ id, runId: id, items: collectEvidence(result.executed) });

    // Depth/impact: propose exploit-CHAIN hypotheses across the in-scope findings
    // (cross-asset allowed; every chain step is re-checked against scope). The AI
    // only hypothesizes — a human verifies. Never throws; worst case zero chains.
    let chainResult = { chains: [], source: 'skipped' };
    try {
      chainResult = await brain.proposeChains(result.findings || [], { chat: llm.chat, scope: engagement.scope });
    } catch (_) { /* keep zero chains */ }
    for (const c of chainResult.chains || []) {
      // AI narrative for each validated chain (business-impact prose for the
      // report). The model narrates; severity stays the code's. Never fatal.
      try {
        const n = await brain.draftChainNarrative(c, { chat: llm.chat });
        if (n && n.source === 'llm') c.narrative = n;
      } catch (_) { /* no narrative → report falls back to placeholders */ }
      chainsStore?.upsert({ id: `${id}:${c.id || c.title || Math.random().toString(36).slice(2)}`, runId: id, ...c });
    }
    for (const c of (chainResult.chains || []).filter((x) => /high|critical/i.test(x.severity || ''))) {
      try { await bot?.notifyFinding({ severity: c.severity, title: `CHAIN: ${c.title}`, target: engagement.name }); } catch (_) {}
    }

    runs?.upsert({
      id, status: 'done', finishedAt: Date.now(),
      budgetUsed: result.budgetUsed,
      counts: { findings: (result.findings || []).length, ranked: ranked.length, reportworthy: (result.reportworthy || []).length, chains: (chainResult.chains || []).length },
      executed: result.executed,
    });
    // Cross-run memory: fold this run's assets + what-paid-off into the store so
    // the next engagement on this scope starts warmer. Best-effort.
    try { memory?.record(engagement, result); } catch (_) {}

    audit?.record('run.done', { id, name: engagement.name, ranked: ranked.length, reportworthy: (result.reportworthy || []).length, chains: (chainResult.chains || []).length }, 'runner');
    return { id, ranked, ...result };
  }

  return { runEngagement };
}
