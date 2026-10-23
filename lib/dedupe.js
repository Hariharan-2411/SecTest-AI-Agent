// Cross-run dedupe. A finding's stable identity is its type+name+host (NOT the
// run-scoped id). A repeat is marked `seen` and MERGED — never dropped, so low
// findings always survive (Phase 1 retain-all rule). Tracks first/last run.
export function fingerprint(f = {}) {
  return [f.type || f.templateId || '', f.name || f.title || '', f.host || f.target || '']
    .join('|')
    .toLowerCase();
}

export function markSeen(findings, { store, runId } = {}) {
  const out = [];
  for (const f of Array.isArray(findings) ? findings : []) {
    const key = fingerprint(f);
    const prev = store && store.get(key, 'key');
    if (prev) {
      store.upsert({ key, firstRun: prev.firstRun, lastRun: runId, count: (prev.count || 1) + 1 }, 'key');
      out.push({ ...f, status: 'seen', firstRun: prev.firstRun, lastRun: runId });
    } else {
      if (store) store.upsert({ key, firstRun: runId, lastRun: runId, count: 1 }, 'key');
      out.push({ ...f, status: 'new', firstRun: runId, lastRun: runId });
    }
  }
  return out;
}
