import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeWebsiteInput, challengeRecordName, challengeRecordValue } from '../src/lib/websiteNormalize.js';

const env = { SF_ALLOW_TEST_HOSTNAMES: 'true' };
const parse = (value, options = {}) => normalizeWebsiteInput(value, { env, nodeEnv: 'test', ...options });

test('normalization lowercases the host, removes one trailing dot and drops the default port', () => {
  for (const input of ['https://Shop.Example.COM./login?x=1', '  SHOP.example.com  ', 'https://shop.example.com:443/a']) {
    const result = parse(input);
    assert.equal(result.ok, true, `${input} should parse`);
    assert.equal(result.value.hostname, 'shop.example.com');
    assert.equal(result.value.scheme, 'https');
    assert.equal(result.value.registrable_domain, 'example.com');
  }
  const explicit = parse('http://shop.example.com:8080/x');
  assert.equal(explicit.value.scheme, 'http');
  assert.equal(explicit.value.hostname, 'shop.example.com');
});

test('an international name is stored as punycode with the Unicode display form and a warning', () => {
  const result = parse('https://münchen.de/');
  assert.equal(result.ok, true);
  assert.equal(result.value.hostname, 'xn--mnchen-3ya.de');
  assert.equal(result.value.hostname_unicode, 'münchen.de');
  assert.equal(result.value.homograph_warning, true);
});

test('a Cyrillic look-alike of a Latin name is flagged', () => {
  const result = parse('https://xn--xample-2of.com/');
  assert.equal(result.ok, true);
  assert.equal(result.value.hostname, 'xn--xample-2of.com');
  assert.equal(result.value.homograph_warning, true);
  assert.notEqual(result.value.hostname_unicode, result.value.hostname);
});

test('IP literals are refused, including numeric and hexadecimal forms', () => {
  for (const input of ['https://203.0.113.10/', 'https://[2001:db8::1]/', 'https://2130706433/', 'https://0x7f.1/']) {
    const result = parse(input);
    assert.equal(result.ok, false);
    assert.equal(result.code, 'ip_address_not_allowed', input);
  }
});

test('embedded credentials are refused', () => {
  const result = parse('https://user:pass@shop.example.com/');
  assert.equal(result.code, 'userinfo_not_allowed');
});

test('the URL parser, not a regular expression, decides the host', () => {
  const result = parse('https://shop.example.com%2f@evil.test/');
  // The URL parser reads evil.test as the host and the rest as user information.
  // Embedded credentials are refused, so the request never becomes a website.
  assert.equal(result.ok, false);
  assert.equal(result.code, 'userinfo_not_allowed');
  const backslash = parse('https://shop.example.com\\@evil.test/');
  assert.equal(backslash.value.hostname, 'shop.example.com');
});

test('only http and https are accepted and a missing scheme becomes https', () => {
  assert.equal(parse('ftp://example.com/file').code, 'unsupported_scheme');
  assert.equal(parse('javascript://example.com/%0aalert(1)').code, 'unsupported_scheme');
  const bare = parse('shop.example.com');
  assert.equal(bare.ok, true);
  assert.equal(bare.value.scheme, 'https');
});

test('reserved, single label and documentation names are refused', () => {
  for (const [input, code] of [
    ['http://localhost/', 'reserved_hostname'],
    ['http://localhost.localhost/', 'reserved_hostname'],
    ['http://intranet/', 'reserved_hostname'],
    ['https://example.com/', 'reserved_hostname'],
    ['https://example.net/', 'reserved_hostname'],
    ['https://example.org/', 'reserved_hostname'],
    ['https://thing.local/', 'reserved_hostname'],
    ['https://thing.internal/', 'reserved_hostname'],
    ['https://thing.invalid/', 'reserved_hostname'],
  ]) {
    const result = parse(input);
    assert.equal(result.ok, false, input);
    assert.equal(result.code, code, input);
  }
});

test('the .test allowance is off by default and cannot be enabled in production', () => {
  const denied = normalizeWebsiteInput('https://shop.example.test', { env: {}, nodeEnv: 'test' });
  assert.equal(denied.code, 'reserved_hostname');
  const production = normalizeWebsiteInput('https://shop.example.test', { env, nodeEnv: 'production', allowTestHostnames: true });
  assert.equal(production.code, 'reserved_hostname');
});

test('public suffixes and private suffixes cannot be claimed', () => {
  for (const input of ['https://co.uk/', 'https://github.io/']) {
    const result = parse(input);
    assert.equal(result.ok, false, input);
    assert.equal(result.code, 'public_suffix_not_allowed', input);
  }
  assert.equal(parse('https://com/').code, 'reserved_hostname');
});

test('malformed hostnames are refused', () => {
  for (const input of [
    'https://shop..example.com/',
    'https://-shop.example.com/',
    'https://shop-.example.com/',
    `https://${'a'.repeat(64)}.example.com/`,
    `https://${'a'.repeat(300)}.com/`,
    'https://shop.example.com\u0000/',
    `https://${'a.'.repeat(130)}com/`,
  ]) {
    const result = parse(input);
    assert.equal(result.ok, false, input);
  }
  assert.equal(parse('').code, 'invalid_url');
  assert.equal(parse('https://').code, 'invalid_url');
});

test('normalization performs no network access', () => {
  const original = globalThis.fetch;
  globalThis.fetch = () => { throw new Error('network access during normalization'); };
  try {
    const result = parse('https://shop.example.com/');
    assert.equal(result.ok, true);
  } finally {
    globalThis.fetch = original;
  }
});

test('the challenge record is service specific and the value contains the token', () => {
  const site = { scope: 'host', hostname: 'shop.example.com', registrable_domain: 'example.com' };
  assert.equal(challengeRecordName(site), '_secureflow-challenge.shop.example.com');
  assert.equal(challengeRecordName({ ...site, scope: 'domain' }), '_secureflow-challenge.example.com');
  assert.equal(challengeRecordValue('abc'), 'secureflow-site-verification=abc');
});
