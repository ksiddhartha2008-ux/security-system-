import { lookup } from 'node:dns/promises';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import { all, run, newId, nowIso } from '../db.js';
import { badRequest } from '../lib/http.js';

/* ------------------------------------------------------------------ *
 * Phishing URL scanner with SSRF protections.
 * - http and https only
 * - every hop (initial and each redirect) is resolved and checked
 * - loopback, private, link local, multicast, reserved and documentation
 *   ranges are refused before any request is made
 * - redirects capped, response size capped, request timeout enforced
 * - remote HTML is only pattern matched; it is never rendered or executed
 * ------------------------------------------------------------------ */

const MAX_REDIRECTS = 3;
const TIMEOUT_MS = 6000;
const MAX_BYTES = 256 * 1024;
const MAX_URL_LENGTH = 2048;

const BLOCKED_V4 = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 4], ['240.0.0.0', 4],
];

function ipv4ToInt(ip) {
  return ip.split('.').reduce((acc, part) => (acc << 8) + Number(part), 0) >>> 0;
}

export function blockedIpReason(ip) {
  if (net.isIPv4(ip)) {
    const value = ipv4ToInt(ip);
    for (const [base, bits] of BLOCKED_V4) {
      const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
      if ((value & mask) >>> 0 === (ipv4ToInt(base) & mask) >>> 0) {
        return `address ${ip} is in a non public range`;
      }
    }
    return null;
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    if (lower === '::1' || lower === '::') return 'IPv6 loopback or unspecified address';
    if (lower.startsWith('::ffff:')) {
      const v4 = lower.slice(7);
      if (net.isIPv4(v4)) return blockedIpReason(v4);
      return 'IPv4 mapped address that could not be validated';
    }
    if (/^f[cd]/.test(lower)) return 'IPv6 unique local address';
    if (/^fe[89ab]/.test(lower)) return 'IPv6 link local address';
    if (/^ff/.test(lower)) return 'IPv6 multicast address';
    if (lower.startsWith('2001:db8')) return 'IPv6 documentation range';
    return null;
  }
  return 'not a valid IP address';
}

export function normalizeUrl(input) {
  let raw = String(input ?? '').trim();
  if (!raw) throw badRequest('Enter a URL to scan');
  if (raw.length > MAX_URL_LENGTH) throw badRequest(`URL is longer than ${MAX_URL_LENGTH} characters`);
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = `https://${raw}`;
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw badRequest('That is not a valid URL');
  }
  if (!['http:', 'https:'].includes(url.protocol)) throw badRequest('Only http and https URLs can be scanned');
  if (url.username || url.password) throw badRequest('URLs with embedded credentials are not scanned');
  const host = url.hostname.toLowerCase();
  if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
    throw badRequest('Local and internal hostnames cannot be scanned');
  }
  if (url.port && !['80', '443', ''].includes(url.port)) {
    // allowed, but flagged by the heuristics
  }
  return url;
}

/** Resolve the host and return the verified address list, or throw if any address is non public. */
async function assertPublicHost(hostname, resolved = new Map()) {
  if (resolved.has(hostname)) return resolved.get(hostname);
  if (net.isIP(hostname)) {
    const reason = blockedIpReason(hostname);
    if (reason) throw badRequest(`Refusing to scan: ${reason}`);
    resolved.set(hostname, [hostname]);
    return [hostname];
  }
  let records;
  try {
    records = await lookup(hostname, { all: true, verbatim: true });
  } catch {
    throw badRequest(`DNS resolution failed for ${hostname}`);
  }
  if (!records.length) throw badRequest(`No DNS records for ${hostname}`);
  for (const record of records) {
    const reason = blockedIpReason(record.address);
    if (reason) throw badRequest(`Refusing to scan ${hostname}: ${reason}`);
  }
  resolved.set(hostname, records.map((r) => r.address));
  return records.map((r) => r.address);
}

const SUSPICIOUS_TLDS = ['zip', 'mov', 'top', 'xyz', 'click', 'country', 'gq', 'tk', 'ml', 'cf', 'work', 'support', 'rest', 'buzz'];
const URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly'];
const BRANDS = ['paypal', 'microsoft', 'google', 'apple', 'amazon', 'netflix', 'office365', 'outlook', 'docusign', 'dropbox', 'coinbase', 'hdfc', 'icici', 'sbi', 'axis'];
const CREDENTIAL_WORDS = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'password', 'wallet', 'invoice', 'unlock', 'confirm'];

const registrableDomain = (hostname) => {
  const parts = hostname.split('.').filter(Boolean);
  return parts.slice(-2).join('.');
};

function heuristicIndicators(url, html, chain) {
  const indicators = [];
  const add = (id, label, weight, detail) => indicators.push({ id, label, weight, detail });
  const host = url.hostname.toLowerCase();
  const domain = registrableDomain(host);

  if (url.protocol === 'http:') add('insecure-scheme', 'Page served over plain HTTP', 12, 'Credentials sent to an HTTP page travel unencrypted.');
  if (net.isIP(host)) add('ip-literal', 'Host is a raw IP address', 26, `Host ${host} has no domain name.`);
  if (host.includes('xn--')) add('punycode', 'Punycode hostname', 16, 'Punycode can render as a lookalike of a known brand.');
  if (url.href.includes('@')) add('userinfo', 'At sign inside the URL', 20, 'Text before @ can disguise the real destination.');
  const labels = host.split('.');
  if (labels.length >= 5) add('subdomain-depth', 'Unusually deep subdomain chain', 10, `${labels.length} labels in the hostname.`);
  if (SUSPICIOUS_TLDS.includes(labels.at(-1))) add('tld', 'High abuse top level domain', 12, `.${labels.at(-1)} has a high share of abuse reports.`);
  for (const brand of BRANDS) {
    if (host.includes(brand) && !domain.startsWith(`${brand}.`)) {
      add('brand-lookalike', `Brand name "${brand}" outside its real domain`, 26, `Real domain for the brand is not ${domain}.`);
      break;
    }
  }
  const pathText = `${url.pathname}${url.search}`.toLowerCase();
  const words = CREDENTIAL_WORDS.filter((w) => pathText.includes(w));
  if (words.length) add('credential-path', 'Credential related words in the path', 8, words.join(', '));
  if (host.length > 40) add('host-length', 'Very long hostname', 8, `${host.length} characters.`);
  if (URL_SHORTENERS.includes(domain)) add('shortener', 'URL shortener hides the destination', 10, domain);
  if (url.port && !['80', '443', ''].includes(url.port)) add('port', 'Non standard port', 8, `Port ${url.port}.`);
  const domains = new Set(chain.map((c) => registrableDomain(new URL(c.url).hostname)));
  if (domains.size > 1) add('cross-domain-redirect', 'Redirect leaves the original domain', 14, [...domains].join(' to '));
  if (html) {
    if (/<input[^>]+type\s*=\s*["']?password/i.test(html)) add('password-form', 'Password field on the landing page', 22, 'The page asks for a password.');
    if (/<iframe[^>]+(hidden|display\s*:\s*none)/i.test(html)) add('hidden-iframe', 'Hidden iframe present', 10, 'Hidden frames are often used for clickjacking or tracking.');
    const formAction = html.match(/<form[^>]+action\s*=\s*["'](https?:\/\/[^"']+)["']/i);
    if (formAction) {
      try {
        const target = new URL(formAction[1]);
        if (target.origin !== url.origin) add('external-form', 'Form posts to another origin', 12, `Credentials would be sent to ${target.origin}.`);
      } catch { /* malformed action attribute */ }
    }
  }
  return indicators;
}

async function fetchOnce(url, address) {
  return new Promise((resolve, reject) => {
    const secure = url.protocol === 'https:';
    const hostIsIp = net.isIP(url.hostname) !== 0;
    const options = {
      method: 'GET',
      hostname: url.hostname,
      port: url.port || (secure ? 443 : 80),
      path: `${url.pathname}${url.search}`,
      headers: {
        'user-agent': 'SecureFlowAI-URLScanner/1.0 (defensive analysis; no script execution)',
        accept: 'text/html,application/xhtml+xml,text/plain;q=0.8',
        connection: 'close',
      },
      timeout: TIMEOUT_MS,
      rejectUnauthorized: true,
      // Pin the validated address: a second DNS answer cannot redirect the
      // socket to a private range between validation and connection.
      lookup: hostIsIp ? undefined : (_hostname, _options, callback) => {
        callback(null, address, net.isIPv6(address) ? 6 : 4);
      },
      servername: secure && !hostIsIp ? url.hostname : undefined,
    };

    const request = (secure ? https : http).request(options, (response) => {
      const contentType = response.headers['content-type'] ?? '';
      const chunks = [];
      let received = 0;
      let settled = false;
      const finish = (value) => {
        if (settled) return;
        settled = true;
        resolve(value);
      };

      response.on('data', (chunk) => {
        if (received >= MAX_BYTES) return;
        chunks.push(chunk);
        received += chunk.length;
      });
      response.on('end', () => {
        const readable = /text\/html|text\/plain|application\/xhtml/i.test(contentType);
        finish({
          status: response.statusCode ?? 0,
          location: response.headers.location,
          contentType,
          body: readable ? Buffer.concat(chunks).subarray(0, MAX_BYTES).toString('utf8') : '',
        });
      });
      response.on('error', (err) => { if (!settled) { settled = true; reject(err); } });
    });

    request.on('timeout', () => {
      const err = new Error('request timed out');
      err.name = 'AbortError';
      request.destroy(err);
    });
    request.on('error', reject);
    request.end();
  });
}

async function reputationFor(url, addresses) {
  const result = { providers: [], checks: [] };
  const vtKey = process.env.VIRUSTOTAL_API_KEY;
  if (vtKey) {
    try {
      const id = Buffer.from(url.href).toString('base64url');
      const res = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
        headers: { 'x-apikey': vtKey }, signal: AbortSignal.timeout(8000),
      });
      if (res.ok) {
        const body = await res.json();
        const stats = body?.data?.attributes?.last_analysis_stats ?? {};
        result.providers.push('VirusTotal');
        result.checks.push({ provider: 'VirusTotal', malicious: stats.malicious ?? 0, suspicious: stats.suspicious ?? 0, harmless: stats.harmless ?? 0, undetected: stats.undetected ?? 0 });
      } else if (res.status === 404) {
        result.providers.push('VirusTotal');
        result.checks.push({ provider: 'VirusTotal', note: 'URL is not in the VirusTotal dataset yet' });
      } else {
        result.providers.push('VirusTotal');
        result.checks.push({ provider: 'VirusTotal', error: `Provider returned HTTP ${res.status}` });
      }
    } catch (err) {
      result.providers.push('VirusTotal');
      result.checks.push({ provider: 'VirusTotal', error: `Lookup failed: ${err.message}` });
    }
  }
  const abuseKey = process.env.ABUSEIPDB_API_KEY;
  const ip = addresses.find((a) => net.isIPv4(a));
  if (abuseKey && ip) {
    try {
      const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
        headers: { Key: abuseKey, Accept: 'application/json' }, signal: AbortSignal.timeout(8000),
      });
      if (res.ok) {
        const body = await res.json();
        result.providers.push('AbuseIPDB');
        result.checks.push({ provider: 'AbuseIPDB', ipAddress: ip, abuseConfidenceScore: body?.data?.abuseConfidenceScore ?? 0, totalReports: body?.data?.totalReports ?? 0 });
      } else {
        result.providers.push('AbuseIPDB');
        result.checks.push({ provider: 'AbuseIPDB', error: `Provider returned HTTP ${res.status}` });
      }
    } catch (err) {
      result.providers.push('AbuseIPDB');
      result.checks.push({ provider: 'AbuseIPDB', error: `Lookup failed: ${err.message}` });
    }
  }
  if (!result.providers.length) {
    result.note = 'No reputation provider configured. Set VIRUSTOTAL_API_KEY or ABUSEIPDB_API_KEY to enrich scans.';
  }
  return result;
}

export async function scanUrl({ url: input, orgId, userId }) {
  const url = normalizeUrl(input);
  const resolved = new Map();
  await assertPublicHost(url.hostname, resolved);

  const chain = [];
  let current = url;
  let html = '';
  let reachable = false;
  let lastStatus = null;
  let contentType = null;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
    let addresses;
    try {
      addresses = await assertPublicHost(current.hostname, resolved);
    } catch (err) {
      chain.push({ url: current.href, error: err.message });
      break;
    }
    let response;
    try {
      response = await fetchOnce(current, addresses[0]);
      reachable = true;
    } catch (err) {
      chain.push({ url: current.href, error: err.name === 'AbortError' ? 'request timed out' : err.message });
      break;
    }
    chain.push({ url: current.href, status: response.status });
    lastStatus = response.status;
    contentType = response.contentType;
    if (response.status >= 300 && response.status < 400 && response.location) {
      if (hop === MAX_REDIRECTS) {
        chain.push({ url: response.location, error: 'redirect limit reached' });
        break;
      }
      let next;
      try {
        next = new URL(response.location, current);
      } catch {
        break;
      }
      if (!['http:', 'https:'].includes(next.protocol)) {
        chain.push({ url: next.href, error: 'redirect to a non http protocol blocked' });
        break;
      }
      try {
        await assertPublicHost(next.hostname, resolved);
      } catch (err) {
        chain.push({ url: next.href, error: err.message });
        break;
      }
      current = next;
      continue;
    }
    html = response.body;
    break;
  }

  const indicators = heuristicIndicators(url, html, chain);
  const score = Math.min(100, indicators.reduce((sum, i) => sum + i.weight, 0));
  const reputation = await reputationFor(url, await assertPublicHost(url.hostname, resolved).catch(() => []));

  let scoreWithReputation = score;
  for (const check of reputation.checks) {
    if (check.malicious > 0) scoreWithReputation += Math.min(40, check.malicious * 8);
    if (check.abuseConfidenceScore > 25) scoreWithReputation += Math.min(25, Math.round(check.abuseConfidenceScore / 4));
  }
  scoreWithReputation = Math.min(100, scoreWithReputation);

  const verdict = scoreWithReputation >= 70 ? 'malicious' : scoreWithReputation >= 40 ? 'suspicious' : 'low_risk';
  const id = newId('phish');
  run(
    `INSERT INTO phishing_scans (id, org_id, url, domain, verdict, risk_score, indicators, redirect_chain, reachable, status, error, reputation, scanned_by, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed', ?, ?, ?, ?)`,
    id, orgId, url.href, url.hostname, verdict, scoreWithReputation, JSON.stringify(indicators),
    JSON.stringify(chain), reachable ? 1 : 0,
    reachable ? null : 'The host did not respond to the scanner within the limits. Heuristics still apply.',
    JSON.stringify(reputation), userId ?? null, nowIso(),
  );

  return {
    id,
    url: url.href,
    domain: url.hostname,
    verdict,
    riskScore: scoreWithReputation,
    indicators,
    redirectChain: chain,
    reachable,
    httpStatus: lastStatus,
    contentType,
    reputation,
    scannedAt: nowIso(),
    note: 'Heuristic analysis of a single page. Not a guarantee that the site is safe.',
  };
}

export function listScans(orgId, limit = 50) {
  return all('SELECT * FROM phishing_scans WHERE org_id = ? ORDER BY created_at DESC LIMIT ?', orgId, limit);
}
