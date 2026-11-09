export const DEMO_ACCOUNTS = [
  { role: 'Admin', email: 'admin@secureflow.dev', password: 'Admin#2026' },
  { role: 'Analyst', email: 'analyst@secureflow.dev', password: 'Analyst#2026' },
  { role: 'Viewer', email: 'viewer@secureflow.dev', password: 'Viewer#2026' },
];

/**
 * Demo mode seeds a workspace with known credentials. It must never be on by
 * default in production, otherwise the first deployment ships with a public
 * admin password. Set SF_DEMO_MODE explicitly there.
 */
export function isDemoMode() {
  if (process.env.SF_DEMO_MODE !== undefined) return process.env.SF_DEMO_MODE === 'true';
  return process.env.NODE_ENV !== 'production';
}
