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
  return { errors, warnings };
}
