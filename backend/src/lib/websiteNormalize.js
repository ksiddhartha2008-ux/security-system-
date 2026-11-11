import { isIP } from 'node:net';
import { domainToUnicode } from 'node:url';
import { getDomain, getPublicSuffix } from 'tldts';

const CONTROL = /[\u0000-\u001f\u007f]/;
const LABEL = /^[a-z0-9-]+$/;
const MAX_INPUT = 2048;

const RESERVED_SUFFIXES = ['.localhost', '.local', '.internal', '.example', '.invalid'];
const RESERVED_NAMES = new Set(['localhost', 'example.com', 'example.net', 'example.org']);

export const normalizeError = (code, message) => ({ ok: false, code, message });

/** Parse the owner supplied URL into a normalized, ASCII hostname. Pure: no network access. */
export function normalizeWebsiteInput(raw, options = {}) {
  const env = options.env ?? process.env;
  const nodeEnv = options.nodeEnv ?? process.env.NODE_ENV ?? 'development';
  const allowTest = (options.allowTestHostnames ?? env.SF_ALLOW_TEST_HOSTNAMES === 'true')
    && nodeEnv !== 'production';

  if (typeof raw !== 'string') return normalizeError('invalid_url', 'Enter a website address.');
  const input = raw.trim();
  if (!input) return normalizeError('invalid_url', 'Enter a website address.');
  if (input.length > MAX_INPUT) return normalizeError('invalid_url', 'The address is longer than 2048 characters.');
  if (CONTROL.test(input)) return normalizeError('invalid_url', 'The address contains control characters.');

  const withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(input) ? input : `https://${input}`;
  let url;
  try {
    url = new URL(withScheme);
  } catch {
    return normalizeError('invalid_url', 'That is not a valid website address.');
  }

  const scheme = url.protocol.replace(':', '');
  if (scheme !== 'http' && scheme !== 'https') {
    return normalizeError('unsupported_scheme', 'Only http and https addresses are supported.');
  }
  if (url.username || url.password) {
    return normalizeError('userinfo_not_allowed', 'Remove the username or password from the address.');
  }

  let hostname = url.hostname;
  if (hostname.endsWith('.')) hostname = hostname.slice(0, -1);
  if (!hostname) return normalizeError('invalid_url', 'The address has no hostname.');

  const labels = hostname.split('.');
  if (labels.some((label) => label.length === 0)) {
    return normalizeError('invalid_url', 'The hostname contains an empty label.');
  }

  const bare = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
  if (isIP(bare) !== 0) {
    return normalizeError('ip_address_not_allowed', 'Enter a domain name, not an IP address.');
  }

  if (labels.length < 2) {
    return normalizeError('reserved_hostname', 'Enter a public domain name, for example example.com.');
  }
  if (hostname.length > 253) return normalizeError('invalid_url', 'The hostname is longer than 253 characters.');
  for (const label of labels) {
    if (label.length > 63) return normalizeError('invalid_url', 'A hostname label is longer than 63 characters.');
    if (label.startsWith('-') || label.endsWith('-')) {
      return normalizeError('invalid_url', 'A hostname label starts or ends with a hyphen.');
    }
    if (!LABEL.test(label)) return normalizeError('invalid_url', 'The hostname contains unsupported characters.');
  }

  if (RESERVED_NAMES.has(hostname)) {
    return normalizeError('reserved_hostname', 'That domain is reserved for documentation and cannot be registered.');
  }
  if (RESERVED_SUFFIXES.some((suffix) => hostname.endsWith(suffix))) {
    return normalizeError('reserved_hostname', 'That hostname is reserved for local or documentation use.');
  }
  if (!allowTest && hostname.endsWith('.test')) {
    return normalizeError('reserved_hostname', 'The .test top level domain is reserved for testing.');
  }
  const platform = String(env.SF_PLATFORM_DOMAINS ?? '')
    .split(',')
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);
  if (platform.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`))) {
    return normalizeError('reserved_hostname', 'That domain belongs to the platform.');
  }

  const pslOptions = { allowPrivateDomains: true };
  const suffix = getPublicSuffix(hostname, pslOptions);
  const registrable = getDomain(hostname, pslOptions);
  if (!suffix || !registrable || suffix === hostname) {
    return normalizeError('public_suffix_not_allowed', 'Enter a registrable domain, not a public suffix.');
  }

  let hostnameUnicode = hostname;
  try {
    hostnameUnicode = domainToUnicode(hostname);
  } catch {
    hostnameUnicode = hostname;
  }

  const homograph = hasMixedScripts(hostnameUnicode) || hostnameUnicode !== hostname;

  return {
    ok: true,
    value: {
      hostname,
      hostname_unicode: hostnameUnicode,
      scheme,
      scope_options: ['host', 'domain'],
      registrable_domain: registrable,
      homograph_warning: homograph,
    },
  };
}

const SCRIPT_TESTS = [
  ['Latin', /\p{Script=Latin}/u],
  ['Cyrillic', /\p{Script=Cyrillic}/u],
  ['Greek', /\p{Script=Greek}/u],
  ['Han', /\p{Script=Han}/u],
  ['Arabic', /\p{Script=Arabic}/u],
  ['Hebrew', /\p{Script=Hebrew}/u],
  ['Hiragana', /\p{Script=Hiragana}/u],
  ['Katakana', /\p{Script=Katakana}/u],
  ['Hangul', /\p{Script=Hangul}/u],
];

/** A label that mixes scripts, or an IDN that differs from its ASCII form, is worth flagging. */
export function hasMixedScripts(unicodeHostname) {
  for (const label of unicodeHostname.split('.')) {
    const scripts = new Set();
    for (const [name, pattern] of SCRIPT_TESTS) {
      for (const char of label) {
        if (pattern.test(char)) { scripts.add(name); break; }
      }
    }
    if (scripts.size > 1) return true;
  }
  return false;
}

/** Verification name: the host for host scope, the registrable domain for domain scope. */
export const verificationName = (site) => (site.scope === 'domain' ? site.registrable_domain : site.hostname);

export const challengeRecordName = (site) => `_secureflow-challenge.${verificationName(site)}`;

export const challengeRecordValue = (token) => `secureflow-site-verification=${token}`;
