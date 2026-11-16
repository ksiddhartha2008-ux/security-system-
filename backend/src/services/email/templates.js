/** HTML and text for the verification email. All dynamic values are escaped. */
export function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

export function verificationEmail({ link, email, expiresAt }) {
  const safeLink = escapeHtml(link);
  const safeEmail = escapeHtml(email);
  const expires = new Date(expiresAt);
  const expiresText = Number.isFinite(expires.getTime()) ? expires.toUTCString() : 'in 24 hours';
  const subject = 'Verify your SecureFlow AI email address';
  const text = [
    'SecureFlow AI',
    '',
    `Confirm that ${email} belongs to you by opening this link:`,
    link,
    '',
    `The link expires ${expiresText}.`,
    'If you did not create a SecureFlow AI account, ignore this message. No account access is granted by this email.',
  ].join('\n');
  const html = `<!doctype html>
<html lang="en">
  <body style="margin:0;padding:24px;background:#0e141f;font-family:system-ui,-apple-system,'Segoe UI',Arial,sans-serif;color:#e9eff9;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;margin:0 auto;background:#131b2a;border:1px solid #253149;border-radius:12px;">
      <tr><td style="padding:24px 24px 8px;">
        <p style="margin:0;font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:#61b3ff;">SecureFlow AI</p>
        <h1 style="margin:10px 0 0;font-size:22px;line-height:1.3;">Verify your email address</h1>
      </td></tr>
      <tr><td style="padding:8px 24px 0;font-size:14px;line-height:1.6;color:#c7d3e6;">
        <p style="margin:0 0 12px;">Confirm that <strong>${safeEmail}</strong> belongs to you. This link is single use and expires ${escapeHtml(expiresText)}.</p>
        <p style="margin:0 0 20px;">
          <a href="${safeLink}" style="display:inline-block;padding:11px 18px;border-radius:8px;background:#3fce8e;color:#08110c;font-weight:600;text-decoration:none;">Verify email</a>
        </p>
        <p style="margin:0 0 8px;font-size:12px;color:#9dacca;">If the button does not work, copy this address into your browser:</p>
        <p style="margin:0 0 20px;font-size:12px;word-break:break-all;"><a href="${safeLink}" style="color:#61b3ff;">${safeLink}</a></p>
      </td></tr>
      <tr><td style="padding:0 24px 24px;font-size:12px;line-height:1.6;color:#74889c;">
        If you did not create a SecureFlow AI account, ignore this message. This email never asks for a password, MFA code or payment detail.
      </td></tr>
    </table>
  </body>
</html>`;
  return { subject, html, text };
}
