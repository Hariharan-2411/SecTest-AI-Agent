// Tiny in-process pub/sub for live dashboard updates. The server owns one bus;
// the audit log and runner emit onto it, and each open SSE connection is a
// subscriber that writes events to the browser. A nudge is enough — the client
// re-pulls the lists on any event — so events stay small and loss is harmless.
export function createEventBus() {
  const subs = new Set();
  return {
    subscribe(fn) {
      subs.add(fn);
      return () => subs.delete(fn);
    },
    emit(event) {
      for (const fn of [...subs]) {
        try { fn(event); } catch (_) { /* a bad subscriber never stops the others */ }
      }
    },
    size: () => subs.size,
  };
}
