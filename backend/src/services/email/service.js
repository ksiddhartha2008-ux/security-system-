import { createResendProvider } from './resend-provider.js';
import { verificationEmail } from './templates.js';

/**
 * Central email service. Authentication routes depend on this interface, not on
 * Resend, so the provider can be replaced without touching them.
 */
export function createEmailService(env = process.env, { provider } = {}) {
  const baseUrl = String(env.APP_BASE_URL || 'http://localhost:4000').replace(/\/+$/, '');
  const from = env.EMAIL_FROM || '';
  const adapter = provider ?? createResendProvider({ apiKey: env.RESEND_API_KEY, from });

  async function sendVerification({ to, token, expiresAt }) {
    if (!adapter.configured) return { ok: false, code: 'not_configured' };
    const link = `${baseUrl}/verify-email?token=${encodeURIComponent(token)}`;
    const message = verificationEmail({ link, email: to, expiresAt });
    return adapter.send({ to, ...message });
  }

  return { available: Boolean(adapter.configured), baseUrl, sendVerification };
}

export const emailService = createEmailService();
