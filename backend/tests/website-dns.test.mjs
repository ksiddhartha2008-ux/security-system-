import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { evaluateTxtRecords, classifyDnsError, createTxtResolver } from '../src/lib/dnsTxt.js';

const expected = 'secureflow-site-verification=token';

test('only an exact, trimmed match verifies', () => {
  assert.equal(evaluateTxtRecords([['secureflow-site-verification=token']], expected), 'ok');
  assert.equal(evaluateTxtRecords([['  secureflow-site-verification=token  ']], expected), 'ok');
  assert.equal(evaluateTxtRecords([['secureflow-site-verification=token-extra']], expected), 'mismatch');
  assert.equal(evaluateTxtRecords([['SECUREFLOW-SITE-VERIFICATION=TOKEN']], expected), 'mismatch');
  assert.equal(evaluateTxtRecords([['prefix secureflow-site-verification=token']], expected), 'mismatch');
  assert.equal(evaluateTxtRecords([['other=value']], expected), 'mismatch');
  assert.equal(evaluateTxtRecords([], expected), 'not_found');
});

test('TXT chunks are joined before comparison', () => {
  assert.equal(evaluateTxtRecords([['secureflow-site-', 'verification=token']], expected), 'ok');
  assert.equal(evaluateTxtRecords([['secureflow-site-', 'verification=token', ' ']], expected), 'ok');
});

test('record and character caps are enforced', () => {
  const many = Array.from({ length: 25 }, (_, index) => [`other-${index}`]);
  assert.equal(evaluateTxtRecords(many, expected), 'mismatch');
  const padding = 'x'.repeat(5000);
  assert.equal(evaluateTxtRecords([[padding], [expected]], expected), 'not_found');
});

test('resolver errors are classified and never treated as a failure', () => {
  assert.equal(classifyDnsError({ code: 'ENODATA' }), 'not_found');
  assert.equal(classifyDnsError({ code: 'ENOTFOUND' }), 'not_found');
  assert.equal(classifyDnsError({ code: 'ETIMEOUT' }), 'resolver_error');
  assert.equal(classifyDnsError({ code: 'ESERVFAIL' }), 'resolver_error');
  assert.equal(classifyDnsError({ code: 'ECONNREFUSED' }), 'resolver_error');
  assert.equal(classifyDnsError(new Error('boom')), 'resolver_error');
});

test('the file resolver is deterministic and reports missing names as ENODATA', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sf-dns-'));
  const file = join(dir, 'dns.json');
  writeFileSync(file, JSON.stringify({
    records: {
      '_secureflow-challenge.shop.example.test': [['secureflow-site-verification=token']],
      '_secureflow-challenge.split.example.test': [['secureflow-site-', 'verification=token']],
    },
    errors: { '_secureflow-challenge.timeout.example.test': 'ETIMEOUT' },
  }));
  const resolver = createTxtResolver({ fakeFile: file });
  assert.deepEqual(await resolver.resolveTxt('_secureflow-challenge.shop.example.test'), [['secureflow-site-verification=token']]);
  assert.deepEqual(await resolver.resolveTxt('_secureflow-challenge.split.example.test'), [['secureflow-site-', 'verification=token']]);
  await assert.rejects(() => resolver.resolveTxt('_secureflow-challenge.missing.example.test'), (error) => error.code === 'ENODATA');
  await assert.rejects(() => resolver.resolveTxt('_secureflow-challenge.timeout.example.test'), (error) => error.code === 'ETIMEOUT');
});
