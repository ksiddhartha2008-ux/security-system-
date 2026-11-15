import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto';
import { networkInterfaces, hostname } from 'node:os';
import net from 'node:net';
import { all, get, run, newId, nowIso, transaction } from '../db.js';
import { badRequest, forbidden, notFound } from '../lib/http.js';

const IPV4_PRIVATE = [
  ['10.0.0.0', 8], ['172.16.0.0', 12], ['192.168.0.0', 16], ['100.64.0.0', 10],
  ['169.254.0.0', 16], ['127.0.0.0', 8], ['0.0.0.0', 8], ['224.0.0.0', 4], ['240.0.0.0', 4],
];
const IPV4_RESERVED = [
  ['192.0.2.0', 24], ['198.51.100.0', 24], ['203.0.113.0', 24], ['198.18.0.0', 15],
];

function ipv4ToInt(address) {
  return address.split('.').reduce((acc, part) => (acc << 8) + Number(part), 0) >>> 0;
}

function inCidr(address, base, bits) {
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return ((ipv4ToInt(address) & mask) >>> 0) === ((ipv4ToInt(base) & mask) >>> 0);
}

/** Classify an address without ever inventing one. Returns null for invalid input. */
export function classifyAddress(value) {
  const address = String(value ?? '').trim();
  const family = net.isIP(address);
  if (!family) return null;
  if (family === 4) {
    if (IPV4_PRIVATE.some(([base, bits]) => inCidr(address, base, bits))) {
      if (address.startsWith('127.')) return { address, family: 'ipv4', scope: 'loopback' };
      if (address.startsWith('169.254.')) return { address, family: 'ipv4', scope: 'link_local' };
      if (address.startsWith('224.') || address.startsWith('239.')) return { address, family: 'ipv4', scope: 'multicast' };
      return { address, family: 'ipv4', scope: 'private' };
    }
    if (IPV4_RESERVED.some(([base, bits]) => inCidr(address, base, bits))) {
      return { address, family: 'ipv4', scope: 'reserved' };
    }
    return { address, family: 'ipv4', scope: 'public' };
  }
  const lower = address.toLowerCase();
  if (lower === '::1') return { address, family: 'ipv6', scope: 'loopback' };
  if (lower === '::') return { address, family: 'ipv6', scope: 'reserved' };
  if (/^fe[89ab]/.test(lower)) return { address, family: 'ipv6', scope: 'link_local' };
  if (/^f[cd]/.test(lower)) return { address, family: 'ipv6', scope: 'private' };
  if (/^ff/.test(lower)) return { address, family: 'ipv6', scope: 'multicast' };
  if (lower.startsWith('2001:db8')) return { address, family: 'ipv6', scope: 'reserved' };
  return { address, family: 'ipv6', scope: 'public' };
}

export function maskAddress(value) {
  const classified = classifyAddress(value);
  if (!classified) return 'invalid';
  // Loopback is never sensitive and masking it produces nonsense such as "1:xxxx".
  if (classified.scope === 'loopback') return classified.address;
  if (classified.family === 'ipv4') {
    const parts = classified.address.split('.');
    return `${parts[0]}.${parts[1]}.${parts[2]}.xxx`;
  }
  const groups = classified.address.split(':');
  const visible = groups.filter(Boolean).slice(0, 3).join(':');
  return `${visible || 'xxxx'}:xxxx:xxxx`;
}

function decodeKey(value) {
  if (!value) return null;
  let key;
  try { key = Buffer.from(String(value), 'base64'); } catch { return null; }
  return key.length === 32 ? key : null;
}

function keyring(env, plural, single) {
  const map = {};
  if (env[plural]) {
    try {
      const parsed = JSON.parse(env[plural]);
      for (const [version, value] of Object.entries(parsed)) {
        const key = decodeKey(value);
        if (key) map[version] = key;
      }
    } catch { /* invalid keyring means no keys, never a silent fallback */ }
  }
  if (!Object.keys(map).length && env[single]) {
    const key = decodeKey(env[single]);
    if (key) map[env.SF_IP_KEY_VERSION || 'v1'] = key;
  }
  return map;
}

export function hmacKeys(env = process.env) {
  return keyring(env, 'SF_IP_HMAC_KEYS', 'SF_IP_HMAC_KEY');
}

export function vaultKeys(env = process.env) {
  return keyring(env, 'SF_IP_VAULT_KEYS', 'SF_IP_VAULT_KEY');
}

export function currentKeyVersion(env = process.env) {
  return env.SF_IP_KEY_VERSION || 'v1';
}

/** Keyed pseudonym. Plain SHA-256 is never used as the only IP protection. */
export function fingerprintAddress(value, { version, env = process.env } = {}) {
  const classified = classifyAddress(value);
  if (!classified) throw badRequest('Not a valid IP address');
  const keys = hmacKeys(env);
  const keyVersion = version ?? currentKeyVersion(env);
  const key = keys[keyVersion];
  if (!key) throw new Error('IP fingerprint key is not configured');
  const digest = createHmac('sha256', key).update(classified.address).digest('hex');
  return { fingerprint: `ipfp_${digest.slice(0, 32)}`, keyVersion };
}

export function encryptAddress(value, { version, env = process.env } = {}) {
  const classified = classifyAddress(value);
  if (!classified) throw badRequest('Not a valid IP address');
  const keys = vaultKeys(env);
  const keyVersion = version ?? currentKeyVersion(env);
  const key = keys[keyVersion];
  if (!key) throw new Error('IP vault key is not configured');
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const ciphertext = Buffer.concat([cipher.update(classified.address, 'utf8'), cipher.final()]);
  return {
    keyVersion,
    nonce: nonce.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
  };
}

export function decryptAddress(record, { env = process.env } = {}) {
  const keys = vaultKeys(env);
  const key = keys[record.key_version];
  if (!key) throw new Error(`No key material for vault version ${record.key_version}`);
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(record.nonce, 'base64'));
  decipher.setAuthTag(Buffer.from(record.tag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(record.ciphertext, 'base64')), decipher.final()]).toString('utf8');
}

export function discoverLocalAddresses() {
  const interfaces = networkInterfaces();
  const host = hostname();
  const managementInterfaces = String(process.env.SF_MANAGEMENT_INTERFACES ?? '')
    .split(',').map((entry) => entry.trim()).filter(Boolean);
  const found = [];
  for (const [name, entries] of Object.entries(interfaces)) {
    for (const entry of entries ?? []) {
      const classified = classifyAddress(entry.address);
      if (!classified) continue;
      found.push({
        address: classified.address,
        family: classified.family,
        scope: classified.scope,
        interface: name,
        hostname: host,
        isManagement: classified.scope === 'loopback' || managementInterfaces.includes(name),
        discoverySource: 'os.networkInterfaces',
      });
    }
  }
  return found;
}

async function discoverPublicAddress(env) {
  const url = env.SF_PUBLIC_IP_URL;
  if (!url) return null;
  if (!/^https:\/\//i.test(url)) throw badRequest('SF_PUBLIC_IP_URL must use HTTPS');
  const response = await fetch(url, { signal: AbortSignal.timeout(4000), headers: { accept: 'text/plain, application/json' } });
  if (!response.ok) throw new Error(`Public IP service returned HTTP ${response.status}`);
  const text = (await response.text()).trim();
  let candidate = text;
  try {
    const parsed = JSON.parse(text);
    candidate = parsed.ip ?? parsed.address ?? text;
  } catch { /* plain text response */ }
  const classified = classifyAddress(candidate);
  if (!classified || classified.scope !== 'public') throw new Error('Public IP service did not return a public address');
  return { ...classified, hostname: hostname(), interface: '', isManagement: false, discoverySource: 'public-ip-service' };
}

function sealIfPossible(addressId, orgId, address) {
  if (!Object.keys(vaultKeys()).length || !Object.keys(hmacKeys()).length) return false;
  const sealed = encryptAddress(address);
  const existing = get('SELECT id FROM ip_vault WHERE org_id = ? AND address_id = ? AND key_version = ?', orgId, addressId, sealed.keyVersion);
  if (existing) return true;
  run(
    `INSERT INTO ip_vault (id, org_id, address_id, fingerprint, key_version, nonce, ciphertext, tag, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    newId('ipv'), orgId, addressId, fingerprintAddress(address).fingerprint, sealed.keyVersion,
    sealed.nonce, sealed.ciphertext, sealed.tag, nowIso(),
  );
  return true;
}

/** Discover and persist the real local addresses of this host. Never fabricates one. */
export async function syncInfrastructureAddresses(orgId, { includePublic = false, env = process.env } = {}) {
  const found = [...discoverLocalAddresses()];
  if (includePublic) {
    const publicAddress = await discoverPublicAddress(env);
    if (publicAddress) found.push(publicAddress);
  }
  let sealed = 0;
  transaction(() => {
    for (const item of found) {
      const existing = get(
        'SELECT * FROM infra_addresses WHERE org_id = ? AND address = ? AND interface = ?',
        orgId, item.address, item.interface,
      );
      const ts = nowIso();
      if (existing) {
        run(
          `UPDATE infra_addresses SET scope = ?, hostname = ?, provider = ?, discovery_source = ?,
             is_management = ?, verified = 1, last_seen_at = ?, updated_at = ? WHERE id = ?`,
          item.scope, item.hostname, 'local', item.discoverySource, item.isManagement ? 1 : 0,
          ts, ts, existing.id,
        );
        if (sealIfPossible(existing.id, orgId, item.address)) sealed += 1;
      } else {
        const id = newId('ip');
        run(
          `INSERT INTO infra_addresses (id, org_id, address, family, scope, interface, hostname, provider,
             discovery_source, verified, is_management, asset_id, first_seen_at, last_seen_at, metadata, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'local', ?, 1, ?, NULL, ?, ?, ?, ?, ?)`,
          id, orgId, item.address, item.family, item.scope, item.interface, item.hostname,
          item.discoverySource, item.isManagement ? 1 : 0, ts, ts,
          JSON.stringify({ note: item.discoverySource === 'public-ip-service' ? 'Public service answer, not verified as the origin address' : 'Observed on this host' }),
          ts, ts,
        );
        if (sealIfPossible(id, orgId, item.address)) sealed += 1;
      }
    }
  });
  return { discovered: found.length, vaultSealed: sealed, vaultConfigured: Object.keys(vaultKeys()).length > 0 };
}

export function listInfrastructureAddresses(orgId, { includeMasked = true } = {}) {
  const rows = all('SELECT * FROM infra_addresses WHERE org_id = ? ORDER BY scope, address', orgId);
  return rows.map((row) => {
    let fingerprint = null;
    try { fingerprint = fingerprintAddress(row.address).fingerprint; } catch { /* key absent */ }
    return {
      id: row.id,
      masked: includeMasked ? maskAddress(row.address) : undefined,
      family: row.family,
      scope: row.scope,
      interface: row.interface,
      hostname: row.hostname,
      provider: row.provider,
      discoverySource: row.discovery_source,
      verified: row.verified === 1,
      isManagement: row.is_management === 1,
      assetId: row.asset_id,
      firstSeenAt: row.first_seen_at,
      lastSeenAt: row.last_seen_at,
      fingerprint,
      fingerprintAvailable: Boolean(fingerprint),
      vaulted: Boolean(get('SELECT id FROM ip_vault WHERE org_id = ? AND address_id = ? LIMIT 1', orgId, row.id)),
    };
  });
}

export function addressIsProtected(orgId, address) {
  const classified = classifyAddress(address);
  if (!classified) return { protected: true, reason: 'invalid_address' };
  if (['private', 'loopback', 'link_local', 'multicast', 'reserved'].includes(classified.scope)) {
    return { protected: true, reason: `non_public_${classified.scope}` };
  }
  const allow = get('SELECT id FROM trishield_allowlist WHERE org_id = ? AND address = ?', orgId, classified.address);
  if (allow) return { protected: true, reason: 'allowlisted' };
  const infra = get('SELECT id FROM infra_addresses WHERE org_id = ? AND address = ? AND is_management = 1', orgId, classified.address);
  if (infra) return { protected: true, reason: 'management_address' };
  const own = get('SELECT id FROM infra_addresses WHERE org_id = ? AND address = ?', orgId, classified.address);
  if (own) return { protected: true, reason: 'secureflow_infrastructure' };
  return { protected: false, reason: null };
}

export function revealAddress(orgId, addressId, user, reason) {
  if (user?.role !== 'admin') throw forbidden('Only an administrator can reveal an original infrastructure address');
  if (!String(reason ?? '').trim()) throw badRequest('A reason is required to reveal an address');
  const address = get('SELECT * FROM infra_addresses WHERE id = ? AND org_id = ?', addressId, orgId);
  if (!address) throw notFound('Address not found');
  const vault = get(
    'SELECT * FROM ip_vault WHERE org_id = ? AND address_id = ? ORDER BY created_at DESC LIMIT 1',
    orgId, addressId,
  );
  if (!vault) throw new Error('This address has no encrypted original record');
  return { address: decryptAddress(vault), keyVersion: vault.key_version, addressId };
}

export function infrastructureSummary(orgId) {
  const rows = all('SELECT scope, COUNT(*) AS count FROM infra_addresses WHERE org_id = ? GROUP BY scope', orgId);
  const counts = Object.fromEntries(rows.map((row) => [row.scope, row.count]));
  return {
    total: rows.reduce((sum, row) => sum + row.count, 0),
    public: counts.public ?? 0,
    private: counts.private ?? 0,
    loopback: counts.loopback ?? 0,
    management: get('SELECT COUNT(*) AS c FROM infra_addresses WHERE org_id = ? AND is_management = 1', orgId)?.c ?? 0,
    vaultConfigured: Object.keys(vaultKeys()).length > 0,
    fingerprintConfigured: Object.keys(hmacKeys()).length > 0,
  };
}

export function originProtectionStatus(env = process.env) {
  return {
    reverseProxyConfigured: Boolean(env.SF_PUBLIC_ORIGIN || env.SF_TRUST_PROXY === 'true'),
    trustedProxy: env.SF_TRUST_PROXY === 'true',
    cdnHeaderCheck: Boolean(env.SF_CDN_HEADER),
    publicIpDiscoveryConfigured: Boolean(env.SF_PUBLIC_IP_URL),
    originHostnameConfigured: Boolean(env.SF_ORIGIN_HOSTNAME),
    note: 'Origin protection is configuration evidence, not proof that the origin is unreachable directly.',
  };
}
