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

export function createRunner({ env = process.env, broker, llm, critic, bot, audit = null, killswitch = null, runs, findingsStore, chainsStore, fingerprintsStore, evidenceStore } = {}) {
  async function runEngagement(engagement) {
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

    const budget = Number(env.RECON_BUDGET || 12);
    let result;
    try {
      result = await brain.runReconLoop({
        scope: engagement.scope,
        chat: makePlanEnsemble(llm.clients),  // both models propose → union of steps
        agentClient,
        approve: (call) => broker.request(call),
        policy: toRiskPolicy(engagement.policy),
        budget,
        seeds: engagement.seeds || [],
        // Dual-model: second opinion that can only tighten decisions. null → off.
        critique: createCriticHook({ critic, scope: engagement.scope }),
      });
    } catch (e) {
      runs?.upsert({ id, status: 'error', error: String(e), finishedAt: Date.now() });
      audit?.record('run.error', { id, name: engagement.name, error: String(e) }, 'runner');
      throw e;
    }

    // Cross-run dedupe: tag new/seen, merge, never drop.
    const ranked = markSeen(result.triage || [], { store: fingerprintsStore, runId: id });
    for (const f of ranked) findingsStore?.upsert({ id: `${id}:${f.id || f.fingerprint || Math.random().toString(36).slice(2)}`, runId: id, ...f });
    for (const f of ranked.filter((x) => x.status === 'new')) {
      audit?.record('finding.new', { name: f.name || f.title, type: f.type || f.templateId, host: f.host || f.target, severity: f.severity }, 'runner');
    }
    // Alert only on findings NEW this run — on a monitored re-run, already-seen
    // findings stay quiet, so a ping always means something changed.
    const newKeys = new Set(ranked.filter((x) => x.status === 'new').map(fingerprint));
    for (const f of result.reportworthy || []) {
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
    audit?.record('run.done', { id, name: engagement.name, ranked: ranked.length, reportworthy: (result.reportworthy || []).length, chains: (chainResult.chains || []).length }, 'runner');
    return { id, ranked, ...result };
  }

  return { runEngagement };
}
