import { useEffect, useState } from 'react';
import { Activity, Building2, KeyRound, PlugZap, ScrollText, ShieldCheck } from 'lucide-react';
import { PageHeader } from '../components/layout';
import {
  Badge, Button, Card, EmptyState, ErrorState, Field, KeyValue, Pagination, StatusBadge,
  TableSkeleton, Tabs, TabPanel, useToast, InlineNotice, CopyButton,
} from '../components/ui';
import { useApi } from '../lib/hooks';
import { api, ApiError } from '../lib/api';
import { formatDate, titleCase } from '../lib/format';
import { useAuth } from '../lib/auth';

type Org = { id: string; name: string; slug: string; plan: string; settings: Record<string, string | number>; createdAt: string; userCount: number; assetCount: number };
type Integration = {
  key: string; name: string; category: string; description: string; status: string;
  envVars: string[]; configured: boolean; detail: string | null; config: Record<string, unknown>;
};
type Audit = { id: string; actorEmail: string; action: string; resourceType: string; resourceId: string | null; ip: string | null; createdAt: string };
type Health = {
  status: string; uptimeSeconds: number; node: string; environment: string;
  checks: { name: string; status: string; detail: string }[];
  counts: { events: number; detections: number; incidents: number; simulations: number };
  checkedAt: string;
};

export default function SettingsPage() {
  const { user, organization, permissions, refresh } = useAuth();
  const toast = useToast();
  const [tab, setTab] = useState<'organization' | 'integrations' | 'audit' | 'health' | 'account' | 'security'>('organization');

  return (
    <>
      <PageHeader title="Settings" subtitle="Workspace configuration, integration status, the audit trail and system health." />
      <Tabs active={tab} onChange={setTab} id="settings" label="Settings sections" tabs={[
        { key: 'organization', label: 'Organization' },
        { key: 'integrations', label: 'Integrations' },
        { key: 'audit', label: 'Audit log' },
        { key: 'health', label: 'System health' },
        { key: 'security', label: 'Security' },
        { key: 'account', label: 'Your account' },
      ]} />

      <TabPanel id="settings" active={tab}>
        {tab === 'organization' && <OrganizationTab canAdmin={permissions.canAdmin} />}
        {tab === 'integrations' && <IntegrationsTab canAdmin={permissions.canAdmin} />}
        {tab === 'audit' && <AuditTab canAdmin={permissions.canAdmin} />}
        {tab === 'health' && <HealthTab />}
        {tab === 'security' && <SecurityTab />}
        {tab === 'account' && <AccountTab />}
      </TabPanel>
      <p className="tiny faint" style={{ marginTop: 18 }}>
        Signed in as {user?.email} · workspace {organization?.name} · {formatDate(new Date().toISOString())}
      </p>
    </>
  );
}

function OrganizationTab({ canAdmin }: { canAdmin: boolean }) {
  const toast = useToast();
  const org = useApi<Org>('/settings/organization');
  const [form, setForm] = useState({ name: '', timezone: 'UTC', retentionDays: 90, dataResidency: 'local', contactEmail: '' });
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!org.data) return;
    setForm({
      name: org.data.name,
      timezone: String(org.data.settings.timezone ?? 'UTC'),
      retentionDays: Number(org.data.settings.retentionDays ?? 90),
      dataResidency: String(org.data.settings.dataResidency ?? 'local'),
      contactEmail: String(org.data.settings.contactEmail ?? ''),
    });
  }, [org.data]);

  if (org.loading) return <Card><TableSkeleton rows={5} cols={2} /></Card>;
  if (org.error || !org.data) return <Card><ErrorState message={org.error ?? 'Organization unavailable'} onRetry={org.refresh} /></Card>;

  const save = async () => {
    setBusy(true);
    try {
      await api.patch('/settings/organization', {
        name: form.name.trim(),
        settings: {
          timezone: form.timezone.trim(), retentionDays: Number(form.retentionDays),
          dataResidency: form.dataResidency.trim(), contactEmail: form.contactEmail.trim() || null,
        },
      });
      toast.push('success', 'Workspace settings saved');
      org.refresh();
    } catch (err) { toast.push('error', 'Could not save', err instanceof ApiError ? err.message : undefined); }
    finally { setBusy(false); }
  };

  return (
    <div className="grid" style={{ gridTemplateColumns: '1.3fr 1fr' }}>
      <Card title="Workspace profile" subtitle="Used across the application and in reports">
        <div className="stack">
          <Field label="Organization name" htmlFor="org-name">
            <input id="org-name" className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} disabled={!canAdmin} />
          </Field>
          <div className="grid grid-2">
            <Field label="Timezone" htmlFor="org-tz" hint="Display hint only; records are stored in UTC.">
              <input id="org-tz" className="input" value={form.timezone} onChange={(e) => setForm({ ...form, timezone: e.target.value })} disabled={!canAdmin} />
            </Field>
            <Field label="Retention target (days)" htmlFor="org-ret" hint="A target value. No automatic deletion job runs in this build.">
              <input id="org-ret" type="number" min={7} max={3650} className="input" value={form.retentionDays} onChange={(e) => setForm({ ...form, retentionDays: Number(e.target.value) })} disabled={!canAdmin} />
            </Field>
          </div>
          <Field label="Data residency" htmlFor="org-res">
            <input id="org-res" className="input" value={form.dataResidency} onChange={(e) => setForm({ ...form, dataResidency: e.target.value })} disabled={!canAdmin} />
          </Field>
          <Field label="Privacy contact email" htmlFor="org-contact" hint="Leave empty if no verified contact exists. Nothing is invented on the privacy page.">
            <input id="org-contact" className="input" value={form.contactEmail} onChange={(e) => setForm({ ...form, contactEmail: e.target.value })} disabled={!canAdmin} placeholder="privacy@your-domain.example" />
          </Field>
          <div className="row" style={{ justifyContent: 'flex-end' }}>
            <Button variant="primary" onClick={save} loading={busy} disabled={!canAdmin}>Save changes</Button>
          </div>
          {!canAdmin && <p className="tiny faint">Only an admin can change workspace settings.</p>}
        </div>
      </Card>
      <Card title="Workspace facts">
        <KeyValue items={[
          { label: 'Slug', value: <span className="mono">{org.data.slug}</span> },
          { label: 'Plan', value: org.data.plan },
          { label: 'Members', value: String(org.data.userCount) },
          { label: 'Assets', value: String(org.data.assetCount) },
          { label: 'Created', value: formatDate(org.data.createdAt) },
        ]} />
        <div className="divider" style={{ margin: '14px 0' }} />
        <p className="small muted">
          Data isolation is enforced on the server: every query is scoped to the organization resolved from your session cookie, never from a
          value the browser sends.
        </p>
      </Card>
    </div>
  );
}

function IntegrationsTab({ canAdmin }: { canAdmin: boolean }) {
  const toast = useToast();
  const integrations = useApi<Integration[]>('/settings/integrations');
  const [testing, setTesting] = useState<string | null>(null);

  const test = async (key: string) => {
    setTesting(key);
    try {
      const result = await api.post<{ status: string; detail: string | null }>(`/settings/integrations/${key}/test`);
      toast.push(result.status === 'connected' || result.status === 'configured' ? 'success' : 'warn', `${key}: ${result.status}`, result.detail ?? undefined);
      integrations.refresh();
    } catch (err) { toast.push('error', 'Test failed', err instanceof ApiError ? err.message : undefined); }
    finally { setTesting(null); }
  };

  const toggle = async (integration: Integration) => {
    try {
      await api.patch(`/settings/integrations/${integration.key}`, { status: integration.status === 'disabled' ? 'unconfigured' : 'disabled' });
      toast.push('success', 'Integration updated');
      integrations.refresh();
    } catch (err) { toast.push('error', 'Update failed', err instanceof ApiError ? err.message : undefined); }
  };

  if (integrations.loading) return <Card><TableSkeleton rows={6} cols={3} /></Card>;
  if (integrations.error) return <Card><ErrorState message={integrations.error} onRetry={integrations.refresh} /></Card>;

  return (
    <>
      <InlineNotice tone="info">
        Secrets are read from environment variables on the server and never stored in the database or sent to the browser. A status of
        <strong> configured</strong> means the variable exists; it is not proof that the remote service works.
      </InlineNotice>
      <div className="grid grid-2" style={{ marginTop: 14 }}>
        {(integrations.data ?? []).map((integration) => (
          <Card key={integration.key} title={integration.name} subtitle={titleCase(integration.category)}
            actions={<StatusBadge status={integration.status} />}>
            <p className="small muted">{integration.description}</p>
            <div className="row wrap" style={{ gap: 5, marginTop: 10 }}>
              {integration.envVars.map((env) => <span className="chip mono" key={env}>{env}</span>)}
            </div>
            {integration.detail && <p className="tiny faint" style={{ marginTop: 8 }}>{integration.detail}</p>}
            <div className="row" style={{ marginTop: 12, gap: 8 }}>
              <Button size="sm" onClick={() => test(integration.key)} loading={testing === integration.key} disabled={!canAdmin}>Test configuration</Button>
              {canAdmin && integration.key !== 'mirofish' && (
                <Button size="sm" variant="ghost" onClick={() => toggle(integration)}>{integration.status === 'disabled' ? 'Enable' : 'Disable'}</Button>
              )}
            </div>
          </Card>
        ))}
      </div>
    </>
  );
}

function AuditTab({ canAdmin }: { canAdmin: boolean }) {
  const [page, setPage] = useState(1);
  const [action, setAction] = useState('');
  const logs = useApi<{ data: Audit[]; meta: { page: number; limit: number; total: number; totalPages: number } }>(
    canAdmin ? `/settings/audit-logs?page=${page}&limit=25${action ? `&action=${encodeURIComponent(action)}` : ''}` : null,
  );

  if (!canAdmin) {
    return <Card><EmptyState title="Admin only" body="The audit trail is visible to workspace admins." icon={<ScrollText size={18} aria-hidden="true" />} /></Card>;
  }

  return (
    <Card bodyClass="">
      <div className="card-head">
        <input className="input" style={{ maxWidth: 260 }} placeholder="Filter by action, for example incident" value={action}
          onChange={(e) => { setAction(e.target.value); setPage(1); }} aria-label="Filter audit log" />
        <span className="tiny faint" style={{ marginLeft: 'auto' }}>{logs.data?.meta.total ?? 0} entries</span>
      </div>
      {logs.loading && !logs.data ? <TableSkeleton rows={8} cols={4} /> : logs.error ? <ErrorState message={logs.error} onRetry={logs.refresh} /> : (
        <>
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>Action</th><th>Resource</th><th>Actor</th><th>IP</th><th className="right">When</th></tr></thead>
              <tbody>
                {logs.data?.data.map((entry) => (
                  <tr key={entry.id}>
                    <td className="mono tiny">{entry.action}</td>
                    <td className="small muted">{entry.resourceType}{entry.resourceId ? ` · ${entry.resourceId.slice(0, 12)}` : ''}</td>
                    <td className="small">{entry.actorEmail}</td>
                    <td className="mono tiny faint">{entry.ip ?? '—'}</td>
                    <td className="right tiny faint">{formatDate(entry.createdAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {logs.data?.data.length === 0 && <EmptyState title="No audit entries" body="Security sensitive actions are written here." icon={<ScrollText size={18} aria-hidden="true" />} />}
          {logs.data && logs.data.data.length > 0 && <Pagination page={logs.data.meta.page} totalPages={logs.data.meta.totalPages} total={logs.data.meta.total} onPage={setPage} />}
        </>
      )}
    </Card>
  );
}

function HealthTab() {
  const health = useApi<Health>('/settings/health');
  if (health.loading) return <Card><TableSkeleton rows={5} cols={2} /></Card>;
  if (health.error || !health.data) return <Card><ErrorState message={health.error ?? 'Health unavailable'} onRetry={health.refresh} /></Card>;
  return (
    <div className="grid" style={{ gridTemplateColumns: '1.2fr 1fr' }}>
      <Card title="Service checks" subtitle={`Checked ${formatDate(health.data.checkedAt)}`} actions={<Badge tone={health.data.status === 'healthy' ? 'mint' : 'medium'}>{health.data.status}</Badge>}>
        <div className="stack" style={{ gap: 10 }}>
          {health.data.checks.map((check) => (
            <div key={check.name} className="row" style={{ gap: 10, alignItems: 'flex-start' }}>
              <span style={{ marginTop: 2 }}>
                {check.status === 'ok' ? <ShieldCheck size={14} color="var(--color-mint)" aria-hidden="true" /> : check.status === 'unconfigured' ? <PlugZap size={14} color="var(--color-faint)" aria-hidden="true" /> : <Activity size={14} color="var(--color-red)" aria-hidden="true" />}
              </span>
              <div style={{ flex: 1 }}>
                <p className="small strong">{check.name}</p>
                <p className="tiny faint">{check.detail}</p>
              </div>
              <StatusBadge status={check.status === 'ok' ? 'connected' : check.status === 'unconfigured' ? 'unconfigured' : 'error'} />
            </div>
          ))}
        </div>
      </Card>
      <Card title="Runtime">
        <KeyValue items={[
          { label: 'Node.js', value: health.data.node },
          { label: 'Environment', value: health.data.environment },
          { label: 'Uptime', value: `${Math.floor(health.data.uptimeSeconds / 60)} minutes` },
          { label: 'Events', value: String(health.data.counts.events) },
          { label: 'Detections', value: String(health.data.counts.detections) },
          { label: 'Incidents', value: String(health.data.counts.incidents) },
          { label: 'Simulations', value: String(health.data.counts.simulations) },
        ]} />
        <div className="divider" style={{ margin: '14px 0' }} />
        <p className="small muted">
          Health checks run against the local database and the optional MiroFish adapter. No external service is contacted unless it is configured.
        </p>
      </Card>
    </div>
  );
}

function AccountTab() {
  const { user, refresh } = useAuth();
  const toast = useToast();
  const [name, setName] = useState(user?.name ?? '');
  const [passwords, setPasswords] = useState({ currentPassword: '', newPassword: '' });
  const [busy, setBusy] = useState(false);

  const saveProfile = async () => {
    setBusy(true);
    try {
      await api.patch('/auth/me', { name: name.trim() });
      await refresh();
      toast.push('success', 'Profile updated');
    } catch (err) { toast.push('error', 'Update failed', err instanceof ApiError ? err.message : undefined); }
    finally { setBusy(false); }
  };

  const changePassword = async () => {
    setBusy(true);
    try {
      await api.patch('/auth/me', passwords);
      setPasswords({ currentPassword: '', newPassword: '' });
      toast.push('success', 'Password changed', 'Other sessions stay signed in until they expire.');
    } catch (err) { toast.push('error', 'Could not change the password', err instanceof ApiError ? err.message : undefined); }
    finally { setBusy(false); }
  };

  return (
    <div className="grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
      <Card title="Profile" subtitle={user?.email}>
        <div className="stack">
          <Field label="Display name" htmlFor="acc-name"><input id="acc-name" className="input" value={name} onChange={(e) => setName(e.target.value)} /></Field>
          <div className="row" style={{ justifyContent: 'flex-end' }}><Button onClick={saveProfile} loading={busy}>Save name</Button></div>
          <KeyValue items={[
            { label: 'Role', value: <Badge tone={user?.role === 'admin' ? 'mint' : 'neutral'}>{user?.role}</Badge> },
            { label: 'Workspace', value: user?.orgName ?? '—' },
          ]} />
        </div>
      </Card>
      <Card title="Password" subtitle="At least 10 characters">
        <div className="stack">
          <Field label="Current password" htmlFor="acc-current"><input id="acc-current" type="password" className="input" autoComplete="current-password" value={passwords.currentPassword} onChange={(e) => setPasswords({ ...passwords, currentPassword: e.target.value })} /></Field>
          <Field label="New password" htmlFor="acc-new"><input id="acc-new" type="password" className="input" autoComplete="new-password" value={passwords.newPassword} onChange={(e) => setPasswords({ ...passwords, newPassword: e.target.value })} /></Field>
          <div className="row" style={{ justifyContent: 'flex-end' }}>
            <Button variant="primary" onClick={changePassword} loading={busy} icon={<KeyRound size={13} aria-hidden="true" />} disabled={!passwords.currentPassword || passwords.newPassword.length < 10}>Change password</Button>
          </div>
        </div>
      </Card>
      <Card title="Workspace membership" className="">
        <div className="row" style={{ gap: 10 }}>
          <Building2 size={16} aria-hidden="true" color="var(--color-mint-bright)" />
          <div>
            <p className="small strong">{user?.orgName}</p>
            <p className="tiny faint">Role based access is enforced on every API request.</p>
          </div>
        </div>
      </Card>
    </div>
  );
}

/* ------------------------------- security ------------------------------- */

type MfaSetup = { secret: string; otpauth: string; recoveryCodes: string[] };

function SecurityTab() {
  const { user, refresh } = useAuth();
  const toast = useToast();
  const [password, setPassword] = useState('');
  const [setup, setSetup] = useState<MfaSetup | null>(null);
  const [code, setCode] = useState('');
  const [disablePassword, setDisablePassword] = useState('');
  const [disableCode, setDisableCode] = useState('');
  const [regenPassword, setRegenPassword] = useState('');
  const [recovery, setRecovery] = useState<string[] | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const start = async () => {
    setError(null);
    if (!password) { setError('Enter your current password to begin'); return; }
    setBusy('start');
    try {
      const data = await api.post<MfaSetup>('/auth/mfa/setup', { password });
      setSetup(data);
      setPassword('');
    } catch (err) { setError(err instanceof ApiError ? err.message : 'Could not start MFA setup'); }
    finally { setBusy(null); }
  };

  const enable = async () => {
    setError(null);
    setBusy('enable');
    try {
      await api.post('/auth/mfa/enable', { code: code.trim() });
      toast.push('success', 'Multi-factor authentication enabled', 'Keep the recovery codes somewhere safe.');
      setSetup(null);
      setCode('');
      await refresh();
    } catch (err) { setError(err instanceof ApiError ? err.message : 'Could not enable MFA'); }
    finally { setBusy(null); }
  };

  const disable = async () => {
    setError(null);
    setBusy('disable');
    try {
      await api.post('/auth/mfa/disable', { password: disablePassword, code: disableCode.trim() });
      toast.push('success', 'Multi-factor authentication disabled');
      setDisablePassword('');
      setDisableCode('');
      setRecovery(null);
      await refresh();
    } catch (err) { setError(err instanceof ApiError ? err.message : 'Could not disable MFA'); }
    finally { setBusy(null); }
  };

  const regenerate = async () => {
    setError(null);
    setBusy('regen');
    try {
      const data = await api.post<{ recoveryCodes: string[] }>('/auth/mfa/recovery-codes', { password: regenPassword });
      setRecovery(data.recoveryCodes);
      setRegenPassword('');
      toast.push('success', 'New recovery codes generated', 'The previous codes no longer work.');
    } catch (err) { setError(err instanceof ApiError ? err.message : 'Could not regenerate codes'); }
    finally { setBusy(null); }
  };

  return (
    <div className="grid" style={{ gridTemplateColumns: '1.25fr 1fr' }}>
      <Card title="Multi-factor authentication" subtitle="Time based one time codes (TOTP), compatible with any authenticator app"
        actions={<Badge tone={user?.mfaEnabled ? 'mint' : 'neutral'}>{user?.mfaEnabled ? 'enabled' : 'not enabled'}</Badge>}>
        {error && <div className="error-box" role="alert" style={{ marginBottom: 12 }}>{error}</div>}

        {user?.mfaEnabled ? (
          <div className="stack">
            <p className="small muted">
              Signing in now needs your password and a six digit code. Recovery codes are the only way back in if you lose the
              authenticator, so store them offline.
            </p>
            <div className="divider" />
            <p className="label">Regenerate recovery codes</p>
            <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
              <input className="input" type="password" style={{ flex: 1, minWidth: 180 }} value={regenPassword}
                onChange={(e) => setRegenPassword(e.target.value)} placeholder="Current password" aria-label="Current password for recovery codes" />
              <Button onClick={regenerate} loading={busy === 'regen'} disabled={!regenPassword}>Generate new codes</Button>
            </div>

            <div className="divider" />
            <p className="label">Disable MFA</p>
            <p className="tiny faint">This lowers the protection on your account. Confirm with your password and a live code.</p>
            <div className="grid grid-2" style={{ gap: 8 }}>
              <input className="input" type="password" value={disablePassword} onChange={(e) => setDisablePassword(e.target.value)} placeholder="Current password" aria-label="Password to disable MFA" />
              <input className="input mono" value={disableCode} onChange={(e) => setDisableCode(e.target.value)} placeholder="Six digit code" aria-label="Code to disable MFA" />
            </div>
            <div className="row" style={{ justifyContent: 'flex-end' }}>
              <Button variant="danger" onClick={disable} loading={busy === 'disable'} disabled={!disablePassword || disableCode.length < 6}>Disable MFA</Button>
            </div>
          </div>
        ) : setup ? (
          <div className="stack">
            <p className="small muted">
              Add this secret to your authenticator app, then enter the current six digit code to finish. The secret is shown once.
            </p>
            <div>
              <p className="label">Secret</p>
              <div className="row" style={{ gap: 8 }}>
                <code className="code-block" tabIndex={0} style={{ flex: 1 }}>{setup.secret}</code>
                <CopyButton value={setup.secret} label="Copy" />
              </div>
            </div>
            <div>
              <p className="label">Setup URI</p>
              <p className="tiny faint" style={{ wordBreak: 'break-all' }}>{setup.otpauth}</p>
            </div>
            <div>
              <p className="label">Recovery codes (shown once)</p>
              <div className="row wrap" style={{ gap: 6, marginTop: 4 }}>
                {setup.recoveryCodes.map((item) => <code key={item} className="chip mono">{item}</code>)}
              </div>
              <div style={{ marginTop: 6 }}><CopyButton value={setup.recoveryCodes.join('\n')} label="Copy all codes" /></div>
            </div>
            <Field label="Confirm with a code" htmlFor="mfa-enable-code">
              <input id="mfa-enable-code" className="input mono" value={code} onChange={(e) => setCode(e.target.value)} placeholder="123456" />
            </Field>
            <div className="row" style={{ justifyContent: 'flex-end', gap: 8 }}>
              <Button variant="ghost" onClick={() => { setSetup(null); setCode(''); }}>Cancel</Button>
              <Button variant="primary" onClick={enable} loading={busy === 'enable'} disabled={code.trim().length < 6}>Enable MFA</Button>
            </div>
          </div>
        ) : (
          <div className="stack">
            <p className="small muted">
              Add a second factor so a stolen password is not enough. You will need an authenticator app that supports TOTP.
            </p>
            <Field label="Confirm your password" htmlFor="mfa-password" hint="Required so a hijacked session cannot enrol a new device.">
              <input id="mfa-password" className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </Field>
            <div className="row" style={{ justifyContent: 'flex-end' }}>
              <Button variant="primary" onClick={start} loading={busy === 'start'} disabled={!password}>Begin setup</Button>
            </div>
          </div>
        )}
      </Card>

      <div className="stack">
        <Card title="Sessions">
          <p className="small muted">
            Sessions are HttpOnly cookies with a seven day expiry. Changing your password revokes every session and issues a new one.
            Disabling a member revokes theirs immediately.
          </p>
          <div className="row" style={{ marginTop: 12 }}>
            <Button size="sm" onClick={async () => {
              try {
                await api.post('/auth/sessions/revoke-others');
                toast.push('success', 'Other sessions revoked');
              } catch (err) { toast.push('error', 'Could not revoke sessions', err instanceof ApiError ? err.message : undefined); }
            }}>Sign out other sessions</Button>
          </div>
        </Card>
        {recovery && (
          <Card title="New recovery codes" subtitle="Store them offline. Each code works once.">
            <div className="row wrap" style={{ gap: 6 }}>
              {recovery.map((item) => <code key={item} className="chip mono">{item}</code>)}
            </div>
            <div style={{ marginTop: 8 }}><CopyButton value={recovery.join('\n')} label="Copy all codes" /></div>
          </Card>
        )}
        <Card title="Why this matters">
          <p className="small muted">
            A password alone is one breach away from full access. With MFA enabled, the login endpoint returns a challenge instead of a
            session, and no cookie is issued until a valid code is presented.
          </p>
        </Card>
      </div>
    </div>
  );
}
