import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createEventBus } from '../lib/events.js';

test('subscribers receive emitted events; unsubscribe stops them', () => {
  const bus = createEventBus();
  const got = [];
  const unsub = bus.subscribe((e) => got.push(e));
  bus.emit({ kind: 'audit', type: 'finding.new' });
  assert.equal(got.length, 1);
  assert.equal(got[0].type, 'finding.new');
  unsub();
  bus.emit({ kind: 'audit', type: 'run.done' });
  assert.equal(got.length, 1); // no longer receiving
  assert.equal(bus.size(), 0);
});

test('a throwing subscriber does not break delivery to the others', () => {
  const bus = createEventBus();
  const got = [];
  bus.subscribe(() => { throw new Error('boom'); });
  bus.subscribe((e) => got.push(e));
  assert.doesNotThrow(() => bus.emit({ kind: 'audit' }));
  assert.equal(got.length, 1);
});
