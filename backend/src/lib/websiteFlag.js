/**
 * Website protection is a phased feature. It is on by default in development so
 * the workflow can be built and tested, and off by default in production until
 * the launch gates in docs/website/STATUS.md are accepted by the owner.
 */
export function websiteProtectionEnabled(env = process.env) {
  const explicit = env.SF_WEBSITE_PROTECTION ?? env.WEBSITE_PROTECTION_ENABLED;
  if (explicit !== undefined && explicit !== '') return String(explicit).toLowerCase() === 'true';
  return (env.NODE_ENV ?? 'development') !== 'production';
}

export const isProduction = (env = process.env) => env.NODE_ENV === 'production';
