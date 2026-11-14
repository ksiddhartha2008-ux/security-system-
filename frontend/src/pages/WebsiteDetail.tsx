import { useCallback, useEffect, useState, Fragment } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import {
  Activity, AlertTriangle, ArrowLeft, CheckCircle2, Clock, Download, Globe2, KeyRound, Lock,
  Plus, RefreshCw, ShieldCheck, Trash2,
} from 'lucide-react';
import { PageHeader } from '../components/layout';
import {
  Badge, Button, Card, Checkbox, ConfirmDialog, CopyButton, ErrorState, Field, InlineNotice,
  KeyValue, Modal, Pagination, RiskBadge, StatusBadge, TableSkeleton, Tabs, TabPanel, useToast,
} from '../components/ui';
import { RecentAuthDialog, isRecentAuthError } from '../components/RecentAuth';
import { api, download, ApiError } from '../lib/api';
import { useAuth } from '../lib/auth';
import { errorMessage, useApi } from '../lib/hooks';
import { formatDate, timeAgo, type Tone } from '../lib/format';
import {
  CONNECTION_TONE, STATUS_LABEL, SITE_STATUS_TONE, VERIFY_MESSAGE, isTestDomain, remaining,
  type ApiKeyRow, type CreatedKey, type WebsiteDetail, type WebsiteDetection, type WebsiteEvent, type WebsiteIncident,
} from '../lib/website';

type Tab = 'overview' | 'events' | 'detections' | 'incidents' | 'keys' | 'verification' | 'settings';
type Page<T> = { data: T[]; meta: { page: number; limit: number; total: number; totalPages: number } };

const EVENT_TYPES = [
  'auth.login_failed', 'auth.login_succeeded', 'auth.password_reset_requested', 'auth.mfa_failed',
  'auth.signup', 'access.denied', 'request.suspicious', 'request.rate_limited', 'app.error',
  'sdk.connectivity_test', 'sdk.heartbeat',
];

export default function WebsiteDetailPage() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const { permissions } = useAuth();
  const detail = useApi<WebsiteDetail>(`/v1/websites/${id}`);
  const [tab, setTab] = useState<Tab>('overview');
  const [recentOpen, setRecentOpen] = useState(false);
  const [pendingAction, setPendingAction] = useState<(() => void) | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [keyModal, setKeyModal] = useState(false);
  const [keyLabel, setKeyLabel] = useState('production');
  const [createdKey, setCreatedKey] = useState<CreatedKey | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState<ApiKeyRow | null>(null);
  const [keysVersion, setKeysVersion] = useState(0);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleteText, setDeleteText] = useState('');
  const [dataDeleteOpen, setDataDeleteOpen] = useState(false);
  const [dataDeleteText, setDataDeleteText] = useState('');
  const [verifyMessage, setVerifyMessage] = useState<string | null>(null);

  const site = detail.data;

  useEffect(() => {
    if (!site || site.status !== 'pending_verification') return undefined;
    const timer = setInterval(() => detail.refresh(), 15_000);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [site?.status]);

  const guard = useCallback((action: () => Promise<void> | void) => {
    const run = async () => {
      try {
        await action();
      } catch (err) {
        if (isRecentAuthError(err)) {
          setPendingAction(() => () => { void run(); });
          setRecentOpen(true);
          return;
        }
        toast.push('error', 'Action failed', errorMessage(err));
      }
    };
    void run();
  }, [toast]);

  const verifyNow = () => guard(async () => {
    setBusy('verify');
    try {
      const result = await api.post<{ status: string; result: string }>(`/v1/websites/${id}/verify`, {});
      setVerifyMessage(VERIFY_MESSAGE[result.result] ?? 'The check finished.');
      if (result.status === 'verified') toast.push('success', 'Ownership verified', 'You can create an API key now.');
      else if (result.result === 'ok') toast.push('success', 'Ownership verified');
      else toast.push('warn', 'Not verified yet', VERIFY_MESSAGE[result.result]);
      detail.refresh();
    } finally {
      setBusy(null);
    }
  });

  const restart = () => guard(async () => {
    setBusy('restart');
    try {
      await api.post(`/v1/websites/${id}/verification/restart`, {});
      toast.push('success', 'New challenge created', 'The previous record is no longer used.');
      setVerifyMessage(null);
      detail.refresh();
    } finally {
      setBusy(null);
    }
  });

  const createKey = () => guard(async () => {
    setBusy('create-key');
    try {
      const result = await api.post<CreatedKey>(`/v1/websites/${id}/keys`, { label: keyLabel });
      setCreatedKey(result);
      setAcknowledged(false);
      setKeyModal(false);
      setKeysVersion((value) => value + 1);
      detail.refresh();
    } finally {
      setBusy(null);
    }
  });

  const revokeKey = () => guard(async () => {
    if (!revokeTarget) return;
    setBusy('revoke');
    try {
      await api.del(`/v1/websites/${id}/keys/${revokeTarget.keyId}`);
      toast.push('success', 'Key revoked', 'The key stops working immediately.');
      setRevokeTarget(null);
      setKeysVersion((value) => value + 1);
      detail.refresh();
    } finally {
      setBusy(null);
    }
  });

  const deleteSite = () => guard(async () => {
    setBusy('delete');
    try {
      await api.del(`/v1/websites/${id}`);
      toast.push('success', 'Website deleted', 'Keys are revoked. Events stay until the retention period ends.');
      navigate('/websites');
    } finally {
      setBusy(null);
    }
  });

  const deleteData = () => guard(async () => {
    setBusy('delete-data');
    try {
      const result = await api.post<{ events: number }>(`/v1/websites/${id}/data-deletion`, { confirm: dataDeleteText });
      toast.push('success', 'Website event data deleted', `${result.events} event(s) removed.`);
      setDataDeleteOpen(false);
      setDataDeleteText('');
      detail.refresh();
    } finally {
      setBusy(null);
    }
  });

  if (detail.loading && !site) {
    return <><PageHeader title="Website" /><Card><TableSkeleton rows={6} cols={3} /></Card></>;
  }
  if (detail.error || !site) {
    return (
      <>
        <PageHeader title="Website" actions={<Button variant="ghost" icon={<ArrowLeft size={14} aria-hidden="true" />} onClick={() => navigate('/websites')}>Back</Button>} />
        <Card><ErrorState message={detail.error ?? 'Website not found'} onRetry={detail.refresh} /></Card>
      </>
    );
  }

  const tabs: { key: Tab; label: string; count?: number }[] = [
    { key: 'overview', label: 'Overview' },
    { key: 'events', label: 'Events' },
    { key: 'detections', label: 'Detections', count: site.stats.detections },
    { key: 'incidents', label: 'Incidents', count: site.stats.incidents },
    { key: 'keys', label: 'Keys', count: site.keysActive },
    { key: 'verification', label: 'Verification' },
    { key: 'settings', label: 'Settings' },
  ];

  return (
    <>
      <PageHeader
        title={site.displayName}
        subtitle={`${site.scheme}://${site.hostname}${site.hostnameUnicode !== site.hostname ? ` (${site.hostnameUnicode})` : ''}`}
        actions={(
          <>
            <Button variant="ghost" icon={<ArrowLeft size={14} aria-hidden="true" />} onClick={() => navigate('/websites')}>Websites</Button>
            <Button icon={<RefreshCw size={14} aria-hidden="true" />} onClick={() => detail.refresh()}>Refresh</Button>
          </>
        )}
      />

      <div className="row wrap" style={{ gap: 8, marginBottom: 14 }}>
        <Badge tone={SITE_STATUS_TONE[site.status] as Tone} dot>{STATUS_LABEL[site.status]}</Badge>
        <Badge tone={CONNECTION_TONE[site.connection.state] as Tone} dot>{site.connection.label}</Badge>
        <Badge tone="neutral">{site.scope === 'host' ? 'host scope' : 'domain scope'}</Badge>
        <Badge tone="neutral">criticality {site.criticality}</Badge>
        {isTestDomain(site.hostname) && <Badge tone="purple">test domain</Badge>}
        {site.verifiedAt && <span className="tiny faint">Verified {formatDate(site.verifiedAt)}</span>}
      </div>

      {site.healthWarnings.map((warning) => (
        <InlineNotice key={warning.code} tone={warning.code === 'lapsed' ? 'error' : 'warn'}>
          <strong>{warning.label}.</strong> {warning.detail}
        </InlineNotice>
      ))}

      {permissions.canAdmin && site.status !== 'verified' && (
        <div className="notice" style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center', margin: '12px 0' }}>
          <ShieldCheck size={15} aria-hidden="true" />
          <span className="small" style={{ flex: 1, minWidth: 200 }}>
            Publish the TXT record, then run a check. We also retry on a schedule until the challenge expires in {site.verification ? remaining(site.verification.expiresAt) : '7 days'}.
          </span>
          <Button size="sm" variant="primary" onClick={verifyNow} loading={busy === 'verify'} type="button">Verify now</Button>
        </div>
      )}

      <Tabs tabs={tabs} active={tab} onChange={setTab} id="website" label="Website sections" />

      <TabPanel id="website" active={tab}>
        {tab === 'overview' && <Overview site={site} onVerify={verifyNow} busy={busy} />}
        {tab === 'events' && <EventsTab siteId={id} />}
        {tab === 'detections' && <DetectionsTab siteId={id} />}
        {tab === 'incidents' && <IncidentsTab siteId={id} />}
        {tab === 'keys' && (
          <KeysTab
            siteId={id}
            site={site}
            canAdmin={permissions.canAdmin}
            version={keysVersion}
            onAdd={() => { setKeyLabel('production'); setKeyModal(true); }}
            onRevoke={(row) => setRevokeTarget(row)}
          />
        )}
        {tab === 'verification' && (
          <VerificationTab site={site} onVerify={verifyNow} onRestart={restart} busy={busy} message={verifyMessage} />
        )}
        {tab === 'settings' && (
          <SettingsTab
            site={site}
            onSaved={detail.refresh}
            onDelete={() => { setDeleteText(''); setDeleteOpen(true); }}
            onDeleteData={() => { setDataDeleteText(''); setDataDeleteOpen(true); }}
          />
        )}
      </TabPanel>

      <Modal
        open={keyModal}
        onClose={() => setKeyModal(false)}
        title="Create API key"
        subtitle="The secret is shown once. Store it in the customer environment, never in this browser."
        footer={(
          <>
            <Button variant="ghost" onClick={() => setKeyModal(false)} type="button">Cancel</Button>
            <Button variant="primary" onClick={createKey} loading={busy === 'create-key'} type="button" icon={<KeyRound size={14} aria-hidden="true" />}>
              Create key
            </Button>
          </>
        )}
      >
        <p className="small muted">Only a hash is stored. This action needs a recent password confirmation.</p>
        <Field label="Label" htmlFor="key-label" hint="For your records, for example the environment name.">
          <input id="key-label" className="input" maxLength={60} value={keyLabel} onChange={(event) => setKeyLabel(event.target.value)} />
        </Field>
      </Modal>

      <Modal
        open={Boolean(createdKey)}
        onClose={() => { if (acknowledged) { setCreatedKey(null); } }}
        title="Copy this key now"
        subtitle="It cannot be shown again."
        footer={(
          <>
            <Button
              variant="primary"
              disabled={!acknowledged}
              onClick={() => { setCreatedKey(null); setKeyLabel('production'); }}
              type="button"
            >
              I stored the key
            </Button>
          </>
        )}
      >
        <div className="notice">
          <Lock size={14} aria-hidden="true" style={{ display: 'inline', marginRight: 6 }} />
          Anyone with this key can send events for this website, and only this website. The key is not written to browser storage or logs.
        </div>
        <pre className="code-block" tabIndex={0} style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{createdKey?.apiKey}</pre>
        <div className="row" style={{ gap: 8 }}>
          <CopyButton value={createdKey?.apiKey ?? ''} label="Copy key" />
          <span className="tiny faint">key id <span className="mono">{createdKey?.keyId}</span></span>
        </div>
        <Checkbox checked={acknowledged} onChange={setAcknowledged} label="I stored the key in the customer environment and understand it cannot be shown again." />
      </Modal>

      <ConfirmDialog
        open={Boolean(revokeTarget)}
        title="Revoke this key"
        body={`Key ${revokeTarget?.keyId ?? ''} stops working immediately. The SDK on the website will receive 401 responses until a new key is installed.`}
        confirmLabel="Revoke key"
        destructive
        loading={busy === 'revoke'}
        onConfirm={revokeKey}
        onClose={() => setRevokeTarget(null)}
      />

      <Modal
        open={deleteOpen}
        onClose={() => setDeleteOpen(false)}
        title="Delete website"
        subtitle="Soft delete. Keys are revoked, the hostname is released, audit records stay."
        footer={(
          <>
            <Button variant="ghost" onClick={() => setDeleteOpen(false)} type="button">Cancel</Button>
            <Button variant="danger" onClick={deleteSite} loading={busy === 'delete'} disabled={deleteText !== site.hostname} type="button">
              Delete website
            </Button>
          </>
        )}
      >
        <p className="small muted">Type <span className="mono">{site.hostname}</span> to confirm. Stored events remain until retention removes them.</p>
        <Field label="Hostname" htmlFor="delete-hostname">
          <input id="delete-hostname" className="input mono" value={deleteText} onChange={(event) => setDeleteText(event.target.value)} />
        </Field>
      </Modal>

      <Modal
        open={dataDeleteOpen}
        onClose={() => setDataDeleteOpen(false)}
        title="Delete website event data"
        subtitle="Removes the events and the idempotency markers for this website. Incidents and detections are kept as audit records."
        footer={(
          <>
            <Button variant="ghost" onClick={() => setDataDeleteOpen(false)} type="button">Cancel</Button>
            <Button variant="danger" onClick={deleteData} loading={busy === 'delete-data'} disabled={dataDeleteText !== site.hostname} type="button">
              Delete event data
            </Button>
          </>
        )}
      >
        <p className="small muted">This cannot be undone. Export first if you need a copy. Type <span className="mono">{site.hostname}</span> to confirm.</p>
        <Field label="Hostname" htmlFor="delete-data-hostname">
          <input id="delete-data-hostname" className="input mono" value={dataDeleteText} onChange={(event) => setDataDeleteText(event.target.value)} />
        </Field>
      </Modal>

      <RecentAuthDialog
        open={recentOpen}
        onClose={() => { setRecentOpen(false); setPendingAction(null); }}
        onConfirmed={() => {
          setRecentOpen(false);
          const action = pendingAction;
          setPendingAction(null);
          action?.();
        }}
      />
    </>
  );
}

function Overview({ site, onVerify, busy }: { site: WebsiteDetail; onVerify: () => void; busy: string | null }) {
  return (
    <div className="website-overview">
      <div className="grid grid-4" style={{ marginBottom: 14 }}>
        {[
          { label: 'Events, 24 hours', value: site.stats.events24h },
          { label: 'Events, 7 days', value: site.stats.events7d },
          { label: 'Detections', value: site.stats.detections },
          { label: 'Open incidents', value: site.stats.incidents },
        ].map((item) => (
          <div className="card kpi" key={item.label}>
            <div className="kpi-label">{item.label}</div>
            <div className="kpi-value">{item.value}</div>
          </div>
        ))}
      </div>

      <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', marginBottom: 14 }}>
        <Card title="Connection" subtitle="Derived from the last accepted event and heartbeat">
          <KeyValue items={[
            { label: 'State', value: <Badge tone={CONNECTION_TONE[site.connection.state] as Tone} dot>{site.connection.label}</Badge> },
            { label: 'Last event', value: site.lastEventAt ? <span title={formatDate(site.lastEventAt)}>{timeAgo(site.lastEventAt)}</span> : 'No event yet' },
            { label: 'Last heartbeat', value: site.lastHeartbeatAt ? <span title={formatDate(site.lastHeartbeatAt)}>{timeAgo(site.lastHeartbeatAt)}</span> : 'No heartbeat yet' },
            { label: 'Heartbeat interval', value: `${Math.round(site.heartbeatSeconds / 60)} minutes` },
            { label: 'First event', value: site.connectedAt ? formatDate(site.connectedAt) : 'Waiting' },
          ]} />
          {site.connection.reason && <p className="tiny faint" style={{ marginTop: 10 }}>{site.connection.reason}</p>}
          {site.stats.events24h === 0 && (site.keysActive ?? 0) > 0 && (
            <div className="notice" style={{ marginTop: 12 }}>
              No event in the last 24 hours. Check that the key is installed on this exact site, that outbound HTTPS is allowed, and that the endpoint is correct.
            </div>
          )}
        </Card>

        <Card title="Verification" subtitle="DNS TXT record">
          {site.verification ? (
            <KeyValue items={[
              { label: 'Status', value: <StatusBadge status={site.verification.status} /> },
              { label: 'Record', value: <span className="mono">{site.verification.recordName}</span> },
              { label: 'Last result', value: site.verification.lastResult ?? 'Not checked yet' },
              { label: 'Last checked', value: site.verification.lastCheckedAt ? formatDate(site.verification.lastCheckedAt) : 'Never' },
              { label: 'Expires', value: site.verification.status === 'pending' ? remaining(site.verification.expiresAt) : formatDate(site.verification.expiresAt) },
            ]} />
          ) : <p className="small muted">No verification record.</p>}
          {site.status !== 'verified' && (
            <div className="row" style={{ marginTop: 12 }}>
              <Button size="sm" variant="primary" onClick={onVerify} loading={busy === 'verify'} type="button">Verify now</Button>
            </div>
          )}
        </Card>
      </div>

      {site.installSnippet && (
        <Card
          title="Install the Node SDK"
          subtitle="Server side only. The key must stay on the server."
          actions={<CopyButton value={site.installSnippet} label="Copy example" />}
          className="website-snippet"
        >
          <pre className="code-block" tabIndex={0}>{site.installSnippet}</pre>
          <p className="tiny faint" style={{ marginTop: 10 }}>
            Set SECUREFLOW_API_KEY in the environment. Set SECUREFLOW_ACTOR_PEPPER to a value you keep; changing it breaks pseudonym continuity.
            Other languages can post to the same endpoint with the documented HTTP API in docs/website/HTTP_API.md.
          </p>
        </Card>
      )}

      <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', margin: '14px 0' }}>
        <Card title="Top source addresses" subtitle="Last 7 days">
          {site.stats.topSources.length === 0 ? <p className="small muted">No address reported yet.</p> : (
            <div className="table-wrap">
              <table className="data" style={{ minWidth: 280 }}>
                <thead><tr><th>Address</th><th className="right">Events</th></tr></thead>
                <tbody>
                  {site.stats.topSources.map((row) => (
                    <tr key={row.ip}><td className="mono">{row.ip}</td><td className="right">{row.count}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        <Card title="Detections by rule" subtitle="All time">
          {site.stats.detectionsByRule.length === 0 ? <p className="small muted">No detection yet.</p> : (
            <div className="table-wrap">
              <table className="data" style={{ minWidth: 280 }}>
                <thead><tr><th>Rule</th><th className="right">Detections</th></tr></thead>
                <tbody>
                  {site.stats.detectionsByRule.map((row) => (
                    <tr key={row.ruleKey ?? 'unknown'}><td className="mono">{row.ruleKey ?? 'unknown'}</td><td className="right">{row.count}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>

      <Card title="Alerts and health" subtitle="Throttled notifications, including the reason when one was suppressed">
        {site.notifications.length === 0 ? <p className="small muted">No notification for this website yet.</p> : (
          <div className="stack" style={{ gap: 10 }}>
            {site.notifications.map((item) => (
              <div key={item.id} className="row-between" style={{ alignItems: 'flex-start', gap: 12 }}>
                <div style={{ minWidth: 0 }}>
                  <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
                    <Badge tone={item.status === 'sent' ? 'mint' : 'amber'}>{item.status}</Badge>
                    <span className="small strong">{item.title}</span>
                  </div>
                  <p className="tiny faint" style={{ marginTop: 3 }}>{item.body}</p>
                </div>
                <span className="tiny faint" title={formatDate(item.createdAt)}>{timeAgo(item.createdAt)}</span>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

function EventsTab({ siteId }: { siteId: string }) {
  const [page, setPage] = useState(1);
  const [type, setType] = useState('');
  const params = new URLSearchParams({ page: String(page), limit: '25', ...(type ? { type } : {}) });
  const result = useApi<Page<WebsiteEvent>>(`/v1/websites/${siteId}/events?${params.toString()}`, [page, type]);
  const [expanded, setExpanded] = useState<string | null>(null);

  return (
    <Card
      title="Events"
      subtitle="Values come from website visitors. They are displayed as text, never as HTML."
      actions={(
        <select className="select" style={{ width: 240 }} value={type} onChange={(event) => { setType(event.target.value); setPage(1); }} aria-label="Filter by event type">
          <option value="">All event types</option>
          {EVENT_TYPES.map((item) => <option key={item} value={item}>{item}</option>)}
        </select>
      )}
      bodyClass=""
      footer={result.data ? <Pagination page={result.data.meta.page} totalPages={result.data.meta.totalPages} total={result.data.meta.total} onPage={setPage} /> : undefined}
    >
      {result.loading && !result.data ? <TableSkeleton rows={6} cols={5} /> : result.error ? (
        <ErrorState message={result.error} onRetry={result.refresh} />
      ) : result.data && result.data.data.length === 0 ? (
        <p className="empty-body" style={{ padding: 24 }}>No event matches this filter.</p>
      ) : (
        <div className="table-wrap">
          <table className="data">
            <thead><tr><th>Time</th><th>Type</th><th>Source</th><th>Account</th><th>Path</th></tr></thead>
            <tbody>
              {result.data?.data.map((event) => (
                <Fragment key={event.id}>
                  <tr key={event.id} className="row-link" onClick={() => setExpanded(expanded === event.id ? null : event.id)}>
                    <td className="tiny muted" title={formatDate(event.occurredAt)}>{timeAgo(event.occurredAt)}</td>
                    <td className="mono tiny">{event.type}</td>
                    <td className="mono tiny">{event.srcIp ?? '—'}</td>
                    <td className="tiny" style={{ maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis' }}>{event.actor ?? '—'}</td>
                    <td className="mono tiny" style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis' }}>{event.path ?? '—'}</td>
                  </tr>
                  {expanded === event.id && (
                    <tr key={`${event.id}-detail`}>
                      <td colSpan={5}>
                        <div className="tiny" style={{ display: 'grid', gap: 6 }}>
                          <div><span className="faint">Event id: </span><span className="mono">{event.id}</span></div>
                          <div><span className="faint">User agent: </span><span className="mono" style={{ wordBreak: 'break-word' }}>{event.userAgent ?? '—'}</span></div>
                          <div><span className="faint">Method and status: </span><span className="mono">{event.method ?? '—'} {event.status ?? ''}</span></div>
                          <div><span className="faint">Trust: </span>{event.trustLevel}{event.ipClass ? `, address class ${event.ipClass}` : ''}</div>
                          <pre className="code-block" style={{ marginTop: 4 }}>{JSON.stringify(event.attributes, null, 2)}</pre>
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function DetectionsTab({ siteId }: { siteId: string }) {
  const [page, setPage] = useState(1);
  const result = useApi<Page<WebsiteDetection>>(`/v1/websites/${siteId}/detections?page=${page}&limit=25`, [page]);
  return (
    <Card
      title="Detections"
      subtitle="Deterministic rules. Every row keeps the factors used to score it."
      bodyClass=""
      footer={result.data ? <Pagination page={result.data.meta.page} totalPages={result.data.meta.totalPages} total={result.data.meta.total} onPage={setPage} /> : undefined}
    >
      {result.loading && !result.data ? <TableSkeleton rows={6} cols={5} /> : result.error ? (
        <ErrorState message={result.error} onRetry={result.refresh} />
      ) : result.data && result.data.data.length === 0 ? (
        <p className="empty-body" style={{ padding: 24 }}>No detection for this website yet.</p>
      ) : (
        <div className="table-wrap">
          <table className="data">
            <thead><tr><th>Time</th><th>Rule</th><th>Severity</th><th className="right">Risk</th><th>Incident</th></tr></thead>
            <tbody>
              {result.data?.data.map((row) => (
                <tr key={row.id}>
                  <td className="tiny muted" title={formatDate(row.detectedAt)}>{timeAgo(row.detectedAt)}</td>
                  <td>
                    <div className="small strong">{row.title}</div>
                    <div className="tiny faint">{row.description}</div>
                    {row.factors.length > 0 && (
                      <div className="tiny faint" style={{ marginTop: 4 }}>{row.factors.map((factor) => `${factor.label}: ${factor.detail}`).join(' · ')}</div>
                    )}
                  </td>
                  <td><Badge tone={row.severity === 'critical' ? 'critical' : row.severity === 'high' ? 'high' : 'medium'} dot>{row.severity}</Badge></td>
                  <td className="right"><RiskBadge score={row.riskScore} /></td>
                  <td className="tiny">{row.incidentId ? <Link to={`/incidents/${row.incidentId}`}>Open incident</Link> : <span className="faint">Not linked</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function IncidentsTab({ siteId }: { siteId: string }) {
  const [page, setPage] = useState(1);
  const result = useApi<Page<WebsiteIncident>>(`/v1/websites/${siteId}/incidents?page=${page}&limit=20`, [page]);
  return (
    <Card
      title="Incidents"
      subtitle="One incident groups detections that share the website, a source address or an account."
      bodyClass=""
      footer={result.data ? <Pagination page={result.data.meta.page} totalPages={result.data.meta.totalPages} total={result.data.meta.total} onPage={setPage} /> : undefined}
    >
      {result.loading && !result.data ? <TableSkeleton rows={5} cols={5} /> : result.error ? (
        <ErrorState message={result.error} onRetry={result.refresh} />
      ) : result.data && result.data.data.length === 0 ? (
        <p className="empty-body" style={{ padding: 24 }}>No incident linked to this website yet.</p>
      ) : (
        <div className="table-wrap">
          <table className="data">
            <thead><tr><th>Reference</th><th>Title</th><th>Priority</th><th>Status</th><th>Detected</th></tr></thead>
            <tbody>
              {result.data?.data.map((row) => (
                <tr key={row.id} className="row-link">
                  <td><Link to={`/incidents/${row.id}`} className="mono">{row.ref}</Link></td>
                  <td className="small">{row.title}</td>
                  <td><Badge tone={row.priority === 'P1' ? 'critical' : row.priority === 'P2' ? 'high' : 'medium'}>{row.priority}</Badge></td>
                  <td><StatusBadge status={row.status} /></td>
                  <td className="tiny muted" title={formatDate(row.detectedAt)}>{timeAgo(row.detectedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function KeysTab({ siteId, site, canAdmin, version, onAdd, onRevoke }: {
  siteId: string; site: WebsiteDetail; canAdmin: boolean; version: number;
  onAdd: () => void; onRevoke: (row: ApiKeyRow) => void;
}) {
  const keys = useApi<ApiKeyRow[]>(canAdmin ? `/v1/websites/${siteId}/keys` : null, [version]);
  return (
    <Card
      title="API keys"
      subtitle="Scoped to events:write for this website only. At most two active keys allow a rotation overlap."
      actions={canAdmin ? (
        <Button size="sm" variant="primary" icon={<Plus size={13} aria-hidden="true" />} onClick={onAdd} disabled={site.status !== 'verified' || (site.keysActive ?? 0) >= 2} type="button">
          Create key
        </Button>
      ) : undefined}
      bodyClass=""
    >
      {!canAdmin ? <p className="empty-body" style={{ padding: 24 }}>Only an administrator can see key metadata.</p>
        : keys.loading && !keys.data ? <TableSkeleton rows={3} cols={4} /> : keys.error ? <ErrorState message={keys.error} onRetry={keys.refresh} />
          : keys.data && keys.data.length === 0 ? (
            <div className="empty" style={{ textAlign: 'left', padding: 24 }}>
              <p className="empty-title">No key yet</p>
              <p className="empty-body" style={{ marginInline: 0, maxWidth: 520 }}>
                {site.status === 'verified' ? 'Create a key, copy it once, then set it as SECUREFLOW_API_KEY on the website server.' : 'Verify ownership first. Keys cannot exist for an unverified website.'}
              </p>
            </div>
          ) : (
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>Key</th><th>Label</th><th>Status</th><th>Created</th><th>Last used</th><th /></tr></thead>
                <tbody>
                  {keys.data?.map((row) => (
                    <tr key={row.id}>
                      <td className="mono tiny">sfk_{row.keyId}_…{row.last4}</td>
                      <td className="small">{row.label}</td>
                      <td><Badge tone={row.status === 'active' ? 'mint' : row.status === 'expired' ? 'amber' : 'neutral'}>{row.status}</Badge></td>
                      <td className="tiny muted" title={formatDate(row.createdAt)}>{timeAgo(row.createdAt)}</td>
                      <td className="tiny muted">{row.lastUsedAt ? timeAgo(row.lastUsedAt) : 'Never'}</td>
                      <td className="right">
                        {row.status === 'active' && (
                          <Button size="sm" variant="ghost" onClick={() => onRevoke(row)} type="button">Revoke</Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
    </Card>
  );
}

function VerificationTab({ site, onVerify, onRestart, busy, message }: {
  site: WebsiteDetail; onVerify: () => void; onRestart: () => void; busy: string | null; message: string | null;
}) {
  const dns = site.dns;
  return (
    <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))' }}>
      <Card title="DNS record" subtitle="Publish this TXT record at your DNS provider">
        {dns ? (
          <div className="stack" style={{ gap: 14 }}>
            {[
              { label: 'Type', value: dns.type },
              { label: 'Relative name', value: dns.relativeName },
              { label: 'Full name', value: dns.fullName },
              { label: 'Value', value: dns.value },
              { label: 'Suggested TTL', value: String(dns.ttl) },
            ].map((row) => (
              <div key={row.label}>
                <p className="tiny faint">{row.label}</p>
                <div className="row" style={{ gap: 8, alignItems: 'flex-start' }}>
                  <code className="mono" style={{ wordBreak: 'break-all', flex: 1 }}>{row.value}</code>
                  <CopyButton value={row.value} label="Copy" />
                </div>
              </div>
            ))}
            <p className="small muted">{dns.sentence}</p>
            <p className="tiny faint">Expires in {remaining(dns.expiresAt)}.</p>
          </div>
        ) : <p className="small muted">No pending challenge. The last challenge is {site.verification?.status ?? 'not created'}.</p>}

        <div className="row" style={{ gap: 8, marginTop: 14, flexWrap: 'wrap' }}>
          <Button variant="primary" onClick={onVerify} loading={busy === 'verify'} type="button" icon={<ShieldCheck size={14} aria-hidden="true" />}>Verify now</Button>
          <Button variant="ghost" onClick={onRestart} loading={busy === 'restart'} type="button" icon={<RefreshCw size={14} aria-hidden="true" />}>New challenge</Button>
        </div>
        {message && <p className="tiny muted" style={{ marginTop: 10 }}>{message}</p>}
        {site.verification?.lastResult && VERIFY_MESSAGE[site.verification.lastResult] && (
          <p className="tiny faint" style={{ marginTop: 8 }}>{VERIFY_MESSAGE[site.verification.lastResult]}</p>
        )}
      </Card>

      <Card title="Check history" subtitle="From the verification record">
        {site.verification ? (
          <KeyValue items={[
            { label: 'Status', value: <StatusBadge status={site.verification.status} /> },
            { label: 'Method', value: 'DNS TXT, exact match' },
            { label: 'Attempts', value: String(site.verification.attemptCount) },
            { label: 'Last checked', value: site.verification.lastCheckedAt ? formatDate(site.verification.lastCheckedAt) : 'Never' },
            { label: 'Last result', value: site.verification.lastResult ?? '—' },
            { label: 'Verified at', value: site.verification.verifiedAt ? formatDate(site.verification.verifiedAt) : 'Not yet' },
            { label: 'Challenge expires', value: formatDate(site.verification.expiresAt) },
            { label: 'Re-checks', value: 'Every 5 minutes for 2 hours, then hourly. Daily after verification.' },
          ]} />
        ) : <p className="small muted">No verification record for this website.</p>}
        <div className="divider" style={{ margin: '14px 0' }} />
        <p className="tiny faint">
          Verification compares the published TXT value exactly. A DNS resolver error never counts as a failed verification and never
          releases the hostname. Failures lasting the grace period lapse the website.
        </p>
      </Card>
    </div>
  );
}

function SettingsTab({ site, onSaved, onDelete, onDeleteData }: {
  site: WebsiteDetail; onSaved: () => void; onDelete: () => void; onDeleteData: () => void;
}) {
  const { permissions } = useAuth();
  const toast = useToast();
  const [name, setName] = useState(site.displayName);
  const [criticality, setCriticality] = useState(site.criticality);
  const [paths, setPaths] = useState(site.sensitivePaths.join('\n'));
  const [busy, setBusy] = useState(false);

  const save = async () => {
    setBusy(true);
    try {
      await api.patch(`/v1/websites/${site.id}`, {
        display_name: name,
        criticality,
        sensitive_paths: paths.split('\n').map((value) => value.trim()).filter(Boolean),
      });
      toast.push('success', 'Settings saved');
      onSaved();
    } catch (err) {
      toast.push('error', 'Could not save', errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))' }}>
      <Card title="Website settings" subtitle="Hostname and scope cannot change. Register a new website instead.">
        <div className="stack" style={{ gap: 14 }}>
          <Field label="Display name" htmlFor="settings-name">
            <input id="settings-name" className="input" maxLength={100} value={name} onChange={(event) => setName(event.target.value)} />
          </Field>
          <Field label="Criticality" htmlFor="settings-criticality" hint="Used for incident priority.">
            <select id="settings-criticality" className="select" value={criticality} onChange={(event) => setCriticality(Number(event.target.value))}>
              {[1, 2, 3, 4, 5].map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
          </Field>
          <Field label="Sensitive paths" htmlFor="settings-paths" hint="One path per line. A prefix match is used, so /.git/ also covers /.git/config.">
            <textarea id="settings-paths" className="textarea mono" rows={7} value={paths} onChange={(event) => setPaths(event.target.value)} />
          </Field>
          <div className="row" style={{ justifyContent: 'flex-end' }}>
            <Button variant="primary" onClick={save} loading={busy} type="button">Save settings</Button>
          </div>
          <KeyValue items={[
            { label: 'Hostname', value: <span className="mono">{site.hostname}</span> },
            { label: 'Scope', value: site.scope },
            { label: 'Registrable domain', value: <span className="mono">{site.registrableDomain}</span> },
            { label: 'Asset', value: site.assetId ? <Link to={`/assets/${site.assetId}`} className="mono">{site.assetId}</Link> : 'Created after verification' },
          ]} />
        </div>
      </Card>

      <Card title="Export and deletion" subtitle="Tenant scoped, recorded in the audit trail">
        <p className="small muted">Export the website, its events, detections, incidents and key metadata as JSON. Secrets are never included.</p>
        <div className="row" style={{ marginTop: 10, gap: 8, flexWrap: 'wrap' }}>
          <Button
            size="sm"
            icon={<Download size={13} aria-hidden="true" />}
            disabled={!permissions.canAdmin}
            onClick={() => download(`/v1/websites/${site.id}/export`, `secureflow-website-${site.id}.json`).catch((err) => toast.push('error', 'Export failed', errorMessage(err)))}
            type="button"
          >
            Export JSON
          </Button>
        </div>
        <div className="divider" style={{ margin: '16px 0' }} />
        <div className="stack" style={{ gap: 10 }}>
          <div>
            <p className="small strong">Delete event data</p>
            <p className="tiny faint">Removes stored website events for this site. Incidents and detections stay as audit records.</p>
            <Button size="sm" variant="ghost" onClick={onDeleteData} disabled={!permissions.canAdmin} type="button">Delete event data</Button>
          </div>
          <div>
            <p className="small strong">Delete website</p>
            <p className="tiny faint">Revokes every key, releases the hostname and keeps audit history. The website stops accepting events.</p>
            <Button size="sm" variant="danger" icon={<Trash2 size={13} aria-hidden="true" />} onClick={onDelete} disabled={!permissions.canAdmin} type="button">Delete website</Button>
          </div>
        </div>
        <p className="tiny faint" style={{ marginTop: 12 }}>
          <AlertTriangle size={12} aria-hidden="true" style={{ display: 'inline', marginRight: 4 }} />
          Deletion needs a recent password confirmation.
        </p>
      </Card>
    </div>
  );
}
