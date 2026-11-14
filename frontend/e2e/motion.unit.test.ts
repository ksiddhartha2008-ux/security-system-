import test from 'node:test';
import assert from 'node:assert/strict';
import { formatMetric } from '../src/lib/motion.ts';

test('groups thousands and keeps integers by default', () => {
  assert.equal(formatMetric(1250, { locale: 'en-US' }), '1,250');
  assert.equal(formatMetric(0, { locale: 'en-US' }), '0');
});

test('honours decimal precision', () => {
  assert.equal(formatMetric(98.75, { decimals: 2, locale: 'en-US' }), '98.75');
  assert.equal(formatMetric(98.75, { decimals: 0, locale: 'en-US' }), '99');
});

test('keeps negative values and rounding', () => {
  assert.equal(formatMetric(-12.5, { decimals: 1, locale: 'en-US' }), '-12.5');
  assert.equal(formatMetric(-1250, { locale: 'en-US' }), '-1,250');
});

test('handles non finite input as zero', () => {
  assert.equal(formatMetric(Number.NaN, { locale: 'en-US' }), '0');
});
