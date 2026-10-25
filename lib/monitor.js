// Continuous monitoring — the unattended payoff. Schedule an engagement to
// re-run on an interval; each cycle drives the full recon/triage loop again and,
// thanks to cross-run dedupe, only *new* findings surface (the runner already
// alerts on new ones only). Monitors are durable: `resume()` re-arms them after
// a restart. Every cycle respects the kill-switch — while halted, cycles are
// skipped, not queued.
//
// Timers are injected (setTimer/clearTimer default to setInterval/clearInterval)
// so the schedule/cycle logic is deterministically testable without real clocks.
import * as brain from '../vendor/brain.mjs';

let counter = 0;
function newId(ts) {
  counter += 1;
  return `mon_${ts.toString(36)}_${counter}`;
}

export function createMonitor({
  runner,
  store,
  audit = null,
  killswitch = null,
  bot = null,
  buildDigest = brain.buildReconDigest,
  formatDigest = brain.formatReconDigest,
  setTimer = setInterval,
  clearTimer = clearInterval,
  now = Date.now,
} = {}) {
  const handles = new Map(); // id → timer handle

  function arm(mon) {
    const h = setTimer(() => { runCycle(mon.id).catch(() => {}); }, mon.intervalMs);
    if (typeof h?.unref === 'function') h.unref();
    handles.set(mon.id, h);
  }

  async function runCycle(id) {
    const mon = store?.get(id);
    if (!mon || mon.status !== 'active') return { skipped: true, reason: 'inactive' };
    if (killswitch?.engaged?.()) {
      audit?.record('monitor.skipped', { monitorId: id, reason: 'kill_switch_engaged' }, 'monitor');
      return { skipped: true, reason: 'kill_switch_engaged' };
    }
    let result;
    try {
      result = await runner.runEngagement(mon.engagement);
    } catch (e) {
      audit?.record('monitor.error', { monitorId: id, error: String(e) }, 'monitor');
      return { error: String(e) };
    }
    const ranked = result?.ranked || [];
    const newFindings = ranked.filter((f) => f.status === 'new');
    const nu = newFindings.length;
    const seen = ranked.filter((f) => f.status === 'seen').length;

    // Auto-triage digest: "what changed, and what to look at first." Built from
    // this cycle's new findings, ranked against the full set. Sent once per cycle
    // (only when something is new), so a monitor stays quiet unless it matters.
    let digest = null;
    try {
      digest = buildDigest(
        {
          newFindings,
          newHosts: [...new Set(newFindings.map((f) => f.host || f.target).filter(Boolean))],
          newEndpoints: [],
        },
        { scope: mon.engagement?.scope, allFindings: ranked, max: 5 }
      );
    } catch (_) { /* digest is best-effort */ }

    store.upsert({ id, lastRunAt: now(), lastRunId: result?.id, runs: (mon.runs || 0) + 1, lastDigest: digest });
    audit?.record('monitor.cycle', { monitorId: id, runId: result?.id, new: nu, seen }, 'monitor');
    if (digest && !digest.empty) { try { await bot?.notifyText?.(formatDigest(digest)); } catch (_) {} }
    return { runId: result?.id, new: nu, seen, digest };
  }

  function schedule(engagement, intervalMs) {
    const id = newId(now());
    const mon = { id, name: engagement?.name || id, engagement, intervalMs, status: 'active', createdAt: now(), runs: 0 };
    store?.upsert(mon);
    arm(mon);
    audit?.record('monitor.scheduled', { monitorId: id, name: mon.name, intervalMs }, 'dashboard');
    return mon;
  }

  function stop(id) {
    const h = handles.get(id);
    if (h !== undefined) { clearTimer(h); handles.delete(id); }
    if (store?.get(id)) store.upsert({ id, status: 'stopped', stoppedAt: now() });
    audit?.record('monitor.stopped', { monitorId: id }, 'dashboard');
    return true;
  }

  function resume() {
    for (const mon of store?.all?.() || []) if (mon.status === 'active') arm(mon);
  }

  return {
    schedule,
    runCycle,
    stop,
    resume,
    list: () => (store?.all?.() || []).filter((m) => m.status === 'active'),
  };
}
