// Kill-switch — the emergency brake for unattended running. One call halts the
// orchestrator: new engagements are refused, in-flight scans throw at the next
// dispatch, scheduled monitors skip their cycles, and pending approvals are
// denied (the caller wires denyAll). Fail-safe + durable: the engaged flag is
// persisted, so a process that restarts while engaged stays halted until a human
// explicitly clears it.
//
// State is a single doc (id 'state') in the injected store — collection('killswitch')
// in production, or any { get(id), upsert(record) } in tests.
const STATE_ID = 'state';

export function createKillSwitch({ store, audit = null, now = Date.now } = {}) {
  function state() {
    return store?.get(STATE_ID) || { id: STATE_ID, engaged: false };
  }
  return {
    state,
    engaged: () => !!state().engaged,
    assert() {
      if (state().engaged) throw new Error('kill_switch_engaged');
    },
    engage(reason = '', by = 'system') {
      const next = { id: STATE_ID, engaged: true, reason, at: now(), by };
      store?.upsert(next);
      audit?.record('killswitch.engaged', { reason }, by);
      return next;
    },
    clear(by = 'system') {
      const next = { id: STATE_ID, engaged: false, reason: '', clearedAt: now(), by };
      store?.upsert(next);
      audit?.record('killswitch.cleared', {}, by);
      return next;
    },
  };
}
