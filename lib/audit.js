// Audit log — an append-only record of every consequential action and decision:
// engagement intake, scan dispatch, approval request/approve/deny/timeout, new
// findings, and kill-switch changes. Who did what, when. Never merged, never
// dropped; the dashboard and `GET /api/audit` read it back in order.
//
// Backed by the atomic JSON store via `collection('audit')` in production (each
// event carries a unique id so upsert always appends), or any injected store
// exposing { all(), upsert(record) } in tests.
let counter = 0;
function newId(ts) {
  counter += 1;
  return `evt_${ts.toString(36)}_${counter}`;
}

export function createAuditLog({ store, now = Date.now, emit = null } = {}) {
  return {
    // record(type, detail?, actor?) → the persisted event. Also nudges the live
    // event bus (if one is wired) so open dashboards refresh immediately.
    record(type, detail = {}, actor = 'system') {
      const ts = now();
      const rec = { id: newId(ts), ts, type, actor, detail };
      store?.upsert(rec);
      try { emit?.(rec); } catch (_) { /* a bus failure never breaks the audit write */ }
      return rec;
    },
    all: () => store?.all?.() || [],
    tail(n) {
      const rows = store?.all?.() || [];
      return n >= 0 ? rows.slice(-n) : rows.slice();
    },
  };
}
