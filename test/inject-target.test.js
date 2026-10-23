import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as brain from '../vendor/brain.mjs';

const { pickInjectionTarget } = brain;

test('picks a param-bearing URL over the root', () => {
  const urls = ['http://h:3000/plain', 'http://h:3000/rest/search?q=1'];
  assert.equal(pickInjectionTarget('h', urls, 'http://h:3000'), 'http://h:3000/rest/search?q=1');
});
test('falls back when no param URL exists for the host', () => {
  assert.equal(pickInjectionTarget('h', ['http://h:3000/plain'], 'http://h:3000'), 'http://h:3000');
});
test('ignores param URLs on a different host', () => {
  assert.equal(pickInjectionTarget('h', ['http://other/a?x=1'], 'http://h:3000'), 'http://h:3000');
});
test('prefers the URL with more parameters', () => {
  const urls = ['http://h/a?x=1', 'http://h/b?x=1&y=2&z=3'];
  assert.equal(pickInjectionTarget('h', urls, 'http://h'), 'http://h/b?x=1&y=2&z=3');
});
