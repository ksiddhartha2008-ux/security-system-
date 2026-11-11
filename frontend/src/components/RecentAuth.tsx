import { useEffect, useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { api, ApiError } from '../lib/api';
import { useAuth } from '../lib/auth';
import { Button, Field, Modal } from './ui';

/**
 * Sensitive website actions (key creation, revocation, deletion) require a
 * password re-entry inside the last ten minutes. When the API answers
 * recent_auth_required the page opens this dialog and retries the action.
 */
export function RecentAuthDialog({ open, onClose, onConfirmed }: {
  open: boolean;
  onClose: () => void;
  onConfirmed: () => void;
}) {
  const { user } = useAuth();
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) { setPassword(''); setCode(''); setError(null); }
  }, [open]);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.post('/auth/step-up', { password, code: code || undefined });
      onConfirmed();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not confirm your password');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Confirm it is you"
      subtitle="Key management and deletion need a recent password confirmation."
      footer={(
        <>
          <Button variant="ghost" onClick={onClose} type="button">Cancel</Button>
          <Button variant="primary" onClick={submit} loading={busy} disabled={!password} type="button">
            <ShieldCheck size={14} aria-hidden="true" /> Confirm
          </Button>
        </>
      )}
    >
      <p className="small muted">
        The confirmation is valid for ten minutes in this session. The password is checked on the server and is never stored.
      </p>
      <Field label="Password" htmlFor="step-up-password">
        <input id="step-up-password" className="input" type="password" autoComplete="current-password"
          value={password} onChange={(event) => setPassword(event.target.value)} />
      </Field>
      {user?.mfaEnabled && (
        <Field label="Authenticator code" htmlFor="step-up-code" hint="Required because multi-factor authentication is enabled.">
          <input id="step-up-code" className="input mono" inputMode="numeric" autoComplete="one-time-code"
            value={code} onChange={(event) => setCode(event.target.value)} />
        </Field>
      )}
      {error && <p className="err" role="alert">{error}</p>}
    </Modal>
  );
}

export const isRecentAuthError = (err: unknown) => err instanceof ApiError && err.code === 'recent_auth_required';
