import { Resend } from 'resend';

/**
 * Resend adapter. A resolved promise is not enough: the SDK returns an error
 * field, and a timeout is treated as a failure. Tokens and keys never appear in
 * the returned detail.
 */
export function createResendProvider({ apiKey, from, client, timeoutMs = 8000 } = {}) {
  const configured = Boolean(apiKey && from);
  const resend = client ?? (configured ? new Resend(apiKey) : null);

  async function send({ to, subject, html, text }) {
    if (!configured || !resend) return { ok: false, code: 'not_configured' };
    try {
      const delivery = resend.emails.send({ from, to: [to], subject, html, text });
      const timeout = new Promise((_, reject) => {
        const timer = setTimeout(() => reject(Object.assign(new Error('email provider timeout'), { code: 'timeout' })), timeoutMs);
        timer.unref?.();
      });
      const { data, error } = await Promise.race([delivery, timeout]);
      if (error) {
        return {
          ok: false,
          code: 'provider_error',
          status: error.statusCode ?? null,
          detail: String(error.name ?? error.message ?? 'provider rejected the message').slice(0, 120),
        };
      }
      return { ok: true, id: data?.id ?? null };
    } catch (error) {
      return {
        ok: false,
        code: error.code === 'timeout' ? 'timeout' : 'provider_error',
        detail: String(error.message ?? 'email delivery failed').slice(0, 120),
      };
    }
  }

  return { configured, send };
}
