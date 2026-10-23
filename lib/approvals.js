// Approval broker — the human-in-the-loop brake for active/destructive steps.
// runReconLoop calls `approve(call)` on any `needs_approval` step; we persist a
// pending request, fire the notifier (bot + dashboard), and SUSPEND until a human
// resolves it from their phone or the dashboard. Fail-safe: timeout = DENY.
//
// Pure-ish and DI-tested: inject `store`, `notify`, and `now`/timer for tests.

let counter = 0;
function newId() {
  counter += 1;
  return `apr_${Date.now().toString(36)}_${counter}`;
}

export function createApprovalBroker({
  store,                       // collection('approvals')
  notify = async () => {},     // (record) => void   — bot/dashboard push
  audit = null,                // optional audit log — records request/decision
  timeoutMs = 30 * 60 * 1000,  // default 30 min → auto-deny
  setTimer = setTimeout,
  clearTimer = clearTimeout,
} = {}) {
  const pending = new Map(); // id → { resolve, timer }

  function settle(id, decision, by = 'system') {
    const entry = pending.get(id);
    if (!entry) return false; // unknown or already settled
    clearTimer(entry.timer);
    pending.delete(id);
    const rec = store?.get(id) || { id };
    store?.upsert({ ...rec, status: decision, decidedAt: Date.now(), decidedBy: by });
    audit?.record(`approval.${decision}`, { id, tool: rec.call?.tool, target: rec.call?.target }, by);
    entry.resolve(decision === 'approve');
    return true;
  }

  return {
    // The function handed to runReconLoop as `approve`.
    request(call) {
      const id = newId();
      const record = {
        id,
        status: 'pending',
        call,                       // { tool, target, profile }
        risk: call?.risk || 'active',
        createdAt: Date.now(),
      };
      store?.upsert(record);
      audit?.record('approval.requested', { id, tool: call?.tool, target: call?.target, risk: record.risk });
      return new Promise((resolve) => {
        const timer = setTimer(() => settle(id, 'timeout'), timeoutMs);
        if (typeof timer?.unref === 'function') timer.unref();
        pending.set(id, { resolve, timer });
        // Notify out-of-band; never let a notifier failure strand the run.
        Promise.resolve(notify(record)).catch(() => {});
      });
    },
    approve: (id, by) => settle(id, 'approve', by),
    deny: (id, by) => settle(id, 'deny', by),
    pendingIds: () => [...pending.keys()],
    list: () => store?.all?.() || [],
  };
}
