import { stricterDecision } from '../vendor/brain.mjs';
// Dual-model critic — turns a critic LLM into the recon loop's `critique` hook.
// It reviews each proposed step and returns a per-step verdict. The brain enforces
// "tighten only", so even a wrong/flaky critic can never loosen a decision or
// bypass scope/approval. Returns null when no critic is configured (single-model).

function safeParse(text) {
  if (typeof text !== 'string') return null;
  let t = text.trim();
  const fence = t.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) t = fence[1].trim();
  if (!t.startsWith('{') && !t.startsWith('[')) {
    const i = t.indexOf('{');
    const j = t.lastIndexOf('}');
    if (i !== -1 && j > i) t = t.slice(i, j + 1);
  }
  try { return JSON.parse(t); } catch (_) { return null; }
}

export function buildCriticPrompt(steps, context, scopeHosts) {
  const s = context.surface || {};
  const payload = steps.map((st, i) => ({
    i,
    tool: st.call && st.call.tool,
    target: st.call && st.call.target,
    risk: st.call && st.call.risk,
    plannerDecision: st.decision,
  }));
  const content =
    'You are a bug-bounty safety CRITIC reviewing recon steps another model proposed. ' +
    'For EACH step choose the safest decision: "allow" (safe, clearly in-scope, justified), ' +
    '"needs_approval" (active/intrusive or uncertain — a human should confirm), or "deny" ' +
    '(out of scope, pointless, or risky). You may only make a step STRICTER than the planner, never looser. ' +
    `In-scope hosts: ${JSON.stringify(scopeHosts)}. ` +
    `Discovered so far: ${(s.subdomains || []).length} subdomains, ${(s.urls || []).length} urls, ${(context.findings || []).length} findings. ` +
    `Proposed steps: ${JSON.stringify(payload)}. ` +
    'Respond with JSON only: {"verdicts":[{"i":0,"decision":"allow|needs_approval|deny","reason":"short"}]}';
  return [{ role: 'user', content }];
}

export function createCriticHook({ critic, scope } = {}) {
  if (!critic || !critic.enabled) return null;
  const clients = critic.clients && critic.clients.length
    ? critic.clients
    : (typeof critic.chat === 'function' ? [critic] : []);
  if (!clients.length) return null;
  const scopeHosts = (scope && Array.isArray(scope.inScope) ? scope.inScope : []).slice(0, 20);

  return async function critique(steps, context) {
    const messages = buildCriticPrompt(steps, context, scopeHosts);
    const replies = await Promise.allSettled(clients.map((c) => c.chat(messages)));
    // Per step, take the STRICTEST verdict across all critics — safest wins, and
    // the brain still merges that with the planner decision (tighten-only).
    const merged = steps.map(() => ({ decision: 'allow', reason: '' }));
    let anyOk = false;
    for (const r of replies) {
      if (r.status !== 'fulfilled') continue;
      const parsed = safeParse(r.value);
      const arr = parsed && Array.isArray(parsed.verdicts) ? parsed.verdicts : null;
      if (!arr) continue;
      anyOk = true;
      steps.forEach((_, idx) => {
        const v = arr.find((x) => x && x.i === idx) || {};
        const stricter = stricterDecision(merged[idx].decision, v.decision);
        if (stricter !== merged[idx].decision) merged[idx] = { decision: stricter, reason: v.reason || stricter };
      });
    }
    if (!anyOk) throw new Error('critic_parse_failed'); // brain keeps planner decisions
    return merged;
  };
}
