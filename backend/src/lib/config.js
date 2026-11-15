export function trishieldFlags(env = process.env) {
  const enabled = env.TRISHIELD_ENABLED !== 'false';
  return {
    enabled,
    network: enabled && env.TRISHIELD_NETWORK_ENABLED !== 'false',
    endpoint: enabled && env.TRISHIELD_ENDPOINT_ENABLED !== 'false',
    ipShield: enabled && env.TRISHIELD_IP_SHIELD_ENABLED !== 'false',
    response: enabled && env.TRISHIELD_RESPONSE_ENABLED !== 'false',
    apply: env.TRISHIELD_FIREWALL_APPLY === 'true',
    autoApply: env.TRISHIELD_AUTO_APPLY === 'true',
  };
}

/**
 * Production configuration validation. Security critical problems are fatal;
 * operational gaps are warnings so a deployment can still be inspected.
 */
export function checkProductionConfig(env = process.env) {
  const errors = [];
  const warnings = [];
  if (env.NODE_ENV !== 'production') return { errors, warnings };

  if (env.SF_DEMO_MODE === 'true' && env.SF_ALLOW_INSECURE_DEMO !== 'true') {
    errors.push('SF_DEMO_MODE must be off in production. Set SF_ALLOW_INSECURE_DEMO=true only for a throwaway demo host.');
  }
  if (env.SF_ALLOW_ORIGIN && !/^https:\/\//i.test(env.SF_ALLOW_ORIGIN)) {
    errors.push('SF_ALLOW_ORIGIN must be an https origin in production.');
  }
  if (env.SF_TRUST_PROXY !== 'true') {
    warnings.push('SF_TRUST_PROXY is not true. If a TLS proxy is in front of the app, client IPs and rate limits will be wrong.');
  }
  if (!env.CLAMAV_HOST) {
    warnings.push('CLAMAV_HOST is not configured. Evidence uploads are stored unscanned and marked not_scanned.');
  }
  if (!env.VIRUSTOTAL_API_KEY && !env.ABUSEIPDB_API_KEY) {
    warnings.push('No reputation provider key is configured. Threat intelligence lookups stay local.');
  }
  if (!env.MIROFISH_BASE_URL) {
    warnings.push('MIROFISH_BASE_URL is not configured. The simulation lab uses the native engine only.');
  }
  if (env.SF_DNS_FAKE_FILE) {
    errors.push('SF_DNS_FAKE_FILE is a test seam and must never be set in production.');
  }
  if (env.SF_ALLOW_TEST_HOSTNAMES === 'true') {
    errors.push('SF_ALLOW_TEST_HOSTNAMES must be off in production.');
  }
  if ((env.SF_WEBSITE_PROTECTION ?? env.WEBSITE_PROTECTION_ENABLED) === 'true') {
    warnings.push('Website protection is enabled in production. Launch gate G1 (verified email addresses) is not implemented; see docs/website/STATUS.md before enabling this for customers.');
  }
  if (env.TRISHIELD_FIREWALL_APPLY === 'true' && !env.SF_IP_HMAC_KEY && !env.SF_IP_HMAC_KEYS) {
    errors.push('Live firewall changes are enabled without an IP fingerprint key. Set SF_IP_HMAC_KEYS so blocked sources can be correlated across rotations.');
  }
  if (env.TRISHIELD_FIREWALL_APPLY === 'true' && env.SF_IP_KEY_VERSION === undefined) {
    warnings.push('SF_IP_KEY_VERSION is not set. Set it so stored fingerprints and vault records state their key version.');
  }
  if (env.TRISHIELD_AUTO_APPLY === 'true' && env.TRISHIELD_FIREWALL_APPLY !== 'true') {
    warnings.push('TRISHIELD_AUTO_APPLY is true but TRISHIELD_FIREWALL_APPLY is off. Automatic blocking will stop for approval.');
  }
  if (!env.SF_IP_HMAC_KEY && !env.SF_IP_HMAC_KEYS) {
    warnings.push('No IP fingerprint key is configured. Infrastructure addresses cannot be correlated pseudonymously.');
  }
  if (!env.SF_IP_VAULT_KEY && !env.SF_IP_VAULT_KEYS) {
    warnings.push('No IP vault key is configured. Original addresses are stored masked only and cannot be revealed.');
  }
  if (!env.SF_CLOUDFLARE_API_TOKEN && !env.SF_MANAGEMENT_INTERFACES) {
    warnings.push('No cloud firewall token and no SF_MANAGEMENT_INTERFACES list are configured. Management addresses are inferred from interface names only.');
  }
  if (env.SF_PUBLIC_IP_URL && !/^https:\/\//i.test(env.SF_PUBLIC_IP_URL)) {
    errors.push('SF_PUBLIC_IP_URL must be an https endpoint in production.');
  }
  return { errors, warnings };
}
