import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createKillSwitch } from '../lib/killswitch.js';

// Single-doc mem store keyed by id, mirroring collection('killswitch').
function docStore() {
  let doc = null;
  return {
    get: (id) => (doc && doc.id === id ? doc : null),
    upsert: (r) => { doc = { ...(doc || {}), ...r }; return doc; },
  };
}

test('starts disengaged; engage() halts and clear() releases', () => {
  const ks = createKillSwitch({ store: docStore() });
  assert.equal(ks.engaged(), false);
  ks.engage('runaway scan', 'dashboard');
  assert.equal(ks.engaged(), true);
  assert.equal(ks.state().reason, 'runaway scan');
  ks.clear('dashboard');
  assert.equal(ks.engaged(), false);
});

test('assert() throws only while engaged', () => {
  const ks = createKillSwitch({ store: docStore() });
  assert.doesNotThrow(() => ks.assert());
  ks.engage('stop');
  assert.throws(() => ks.assert(), /kill_switch_engaged/);
  ks.clear();
  assert.doesNotThrow(() => ks.assert());
});

test('engage/clear are recorded to the audit log', () => {
  const events = [];
  const audit = { record: (type, detail, actor) => events.push({ type, detail, actor }) };
  const ks = createKillSwitch({ store: docStore(), audit });
  ks.engage('reason', 'tester');
  ks.clear('tester');
  assert.deepEqual(events.map((e) => e.type), ['killswitch.engaged', 'killswitch.cleared']);
  assert.equal(events[0].detail.reason, 'reason');
  assert.equal(events[0].actor, 'tester');
});

test('fail-safe: a store already marked engaged stays halted after construction', () => {
  const store = docStore();
  store.upsert({ id: 'state', engaged: true, reason: 'persisted' });
  const ks = createKillSwitch({ store });
  assert.equal(ks.engaged(), true); // survives a restart
});
