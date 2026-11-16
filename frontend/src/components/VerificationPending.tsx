import { useState } from 'react';
import { api } from '../lib/api';

/**
 * Shown instead of the workspace when the signed-in account has not verified its
 * email. The backend refuses every other route; this screen only offers the
 * allowed actions: resend, sign out and read the address.
 */
export function VerificationPending({ email, onLogout }: { email: string; onLogout: () => void }) {
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);

  const resend = async () => {
    setBusy(true);
    try {
      await api.post('/auth/resend-verification');
    } catch {
      // The response is neutral by design; the same message is shown either way.
    }
    setSent(true);
    setBusy(false);
  };

  return (
    <div className="verification-gate">
      <div className="card verification-card">
        <span className="brand-mark" aria-hidden="true">SF</span>
        <h1>Verify your email</h1>
        <p className="small muted">
          We sent a verification link to <strong>{email}</strong>. Open it to unlock the workspace.
          The link is single use and expires in 24 hours.
        </p>
        {sent && (
          <p className="small" role="status">
            If this account needs verification, a new message will be sent. Check the inbox and the spam folder.
          </p>
        )}
        <div className="row" style={{ gap: 8, marginTop: 8 }}>
          <button className="btn btn-primary" type="button" onClick={resend} disabled={busy}>
            {busy ? 'Sending...' : 'Resend email'}
          </button>
          <button className="btn btn-ghost" type="button" onClick={onLogout}>Sign out</button>
        </div>
        <p className="tiny faint">
          That email never asks for a password, MFA code or payment detail. If you did not create this account, sign out and ignore it.
        </p>
      </div>
    </div>
  );
}
