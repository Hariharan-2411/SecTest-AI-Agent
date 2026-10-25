// Cross-run memory (#5) — so the brain compounds instead of starting cold every
// engagement. Keyed by the engagement's scope, it persists the discovered asset
// inventory and which tools have paid off (produced findings) on this target.
// On the next run the orchestrator feeds known assets back as seeds and hands the
// planner the "what paid off here" list. Backed by collection('memory').
export function scopeKey(engagement) {
  const inScope = engagement && engagement.scope && Array.isArray(engagement.scope.inScope)
    ? engagement.scope.inScope
    : [];
  const key = [...inScope].map((s) => String(s).toLowerCase()).sort().join(',');
  return key || '(empty)';
}

const EMPTY = { knownAssets: [], paidOff: [] };

export function createMemory({ store } = {}) {
  function recall(engagement) {
    try {
      const rec = store?.get(scopeKey(engagement));
      if (!rec) return { ...EMPTY };
      return {
        knownAssets: Array.isArray(rec.knownAssets) ? rec.knownAssets : [],
        // strongest-first so the planner sees the best bets at the front
        paidOff: (Array.isArray(rec.paidOff) ? rec.paidOff : []).slice().sort((a, b) => (b.count || 0) - (a.count || 0)),
      };
    } catch (_) {
      return { ...EMPTY };
    }
  }

  function record(engagement, result) {
    try {
      if (!engagement || !result) return;
      const id = scopeKey(engagement);
      const prev = store?.get(id) || { id, knownAssets: [], paidOff: [] };

      // Merge discovered assets (subdomains + urls + hosts), deduped.
      const s = result.surface || {};
      const incoming = [...(s.subdomains || []), ...(s.urls || []), ...(s.hosts || [])]
        .filter((x) => typeof x === 'string');
      const knownAssets = [...new Set([...(prev.knownAssets || []), ...incoming])];

      // Accumulate tool → productive-run count (only runs that actually found something).
      const counts = new Map((prev.paidOff || []).map((p) => [p.tool, p.count || 0]));
      for (const e of Array.isArray(result.executed) ? result.executed : []) {
        if (e && e.ran && (e.found || 0) > 0 && e.call && e.call.tool) {
          counts.set(e.call.tool, (counts.get(e.call.tool) || 0) + 1);
        }
      }
      const paidOff = [...counts.entries()].map(([tool, count]) => ({ tool, count })).sort((a, b) => b.count - a.count);

      store?.upsert({ id, knownAssets, paidOff, updatedAt: Date.now() });
    } catch (_) { /* memory is best-effort — never break a run */ }
  }

  return { recall, record };
}
