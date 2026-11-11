import { useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Activity, AlertTriangle, Globe2, Plus, RefreshCw, ShieldCheck } from 'lucide-react';
import { PageHeader } from '../components/layout';
import { Badge, Button, Card, EmptyState, ErrorState, SearchInput, TableSkeleton } from '../components/ui';
import { useApi, useDebounced } from '../lib/hooks';
import { useAuth } from '../lib/auth';
import { formatDate, timeAgo, type Tone } from '../lib/format';
import {
  STATUS_LABEL, SITE_STATUS_TONE, CONNECTION_TONE, isTestDomain, type Website, type SiteStatus,
} from '../lib/website';

type Summary = { total: number; verified: number; pending: number; attention: number; connected: number };
type ListPayload = { data: Website[]; meta: { summary: Summary } };

export default function WebsitesPage() {
  const { permissions, features } = useAuth();
  const navigate = useNavigate();
  const [q, setQ] = useState('');
  const [status, setStatus] = useState('');
  const debounced = useDebounced(q, 300);
  const path = features.websiteProtection
    ? `/v1/websites?${new URLSearchParams({ ...(debounced ? { q: debounced } : {}), ...(status ? { status } : {}) }).toString()}`
    : null;
  const list = useApi<ListPayload>(path, [debounced, status]);
  const sites = list.data?.data ?? [];
  const summary = list.data?.meta.summary;

  const empty = useMemo(() => sites.length === 0 && !debounced && !status, [sites.length, debounced, status]);

  if (!features.websiteProtection) {
    return (
      <>
        <PageHeader title="Websites" subtitle="Website protection is not enabled in this environment." />
        <Card>
          <p className="small muted">
            The feature flag is off. An administrator can enable it with SF_WEBSITE_PROTECTION=true where the launch gates
            in docs/website/STATUS.md are accepted. The API answers 404 while the flag is off.
          </p>
        </Card>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Websites"
        subtitle="Register a website, prove ownership with DNS, issue a scoped API key and follow the events it sends."
        actions={(
          <>
            <Button icon={<RefreshCw size={14} aria-hidden="true" />} onClick={() => list.refresh()}>Refresh</Button>
            {permissions.canAdmin && (
              <Button variant="primary" icon={<Plus size={14} aria-hidden="true" />} onClick={() => navigate('/websites/new')}>
                Add website
              </Button>
            )}
          </>
        )}
      />

      <div className="grid grid-4" style={{ marginBottom: 14 }}>
        {[
          { label: 'Websites', value: summary?.total ?? 0, icon: <Globe2 size={13} aria-hidden="true" /> },
          { label: 'Verified', value: summary?.verified ?? 0, icon: <ShieldCheck size={13} aria-hidden="true" /> },
          { label: 'Waiting for verification', value: summary?.pending ?? 0, icon: <RefreshCw size={13} aria-hidden="true" /> },
          { label: 'Connected', value: summary?.connected ?? 0, icon: <Activity size={13} aria-hidden="true" /> },
        ].map((item) => (
          <div className="card kpi" key={item.label}>
            <div className="kpi-label">{item.icon}{item.label}</div>
            <div className="kpi-value">{item.value}</div>
          </div>
        ))}
      </div>

      {summary && summary.attention > 0 && (
        <div className="notice" style={{ marginBottom: 14 }}>
          <AlertTriangle size={14} aria-hidden="true" style={{ marginRight: 6, display: 'inline' }} />
          {summary.attention} website{summary.attention === 1 ? '' : 's'} need attention: verification lapsed or the challenge expired.
        </div>
      )}

      <Card
        title="Registered websites"
        subtitle="Verification and connection status come from stored evidence, not from a stored label."
        actions={(
          <div className="toolbar">
            <SearchInput value={q} onChange={setQ} placeholder="Search name or hostname" />
            <select className="select" style={{ width: 190 }} value={status} onChange={(event) => setStatus(event.target.value)} aria-label="Filter by status">
              <option value="">All statuses</option>
              <option value="verified">Verified</option>
              <option value="pending_verification">Pending verification</option>
              <option value="expired">Expired</option>
              <option value="lapsed">Lapsed</option>
            </select>
          </div>
        )}
        bodyClass=""
      >
        {list.loading && !list.data ? <TableSkeleton rows={5} cols={6} /> : list.error ? (
          <ErrorState message={list.error} onRetry={list.refresh} />
        ) : empty ? (
          <EmptyState
            icon={<Globe2 size={18} aria-hidden="true" />}
            title="No website registered yet"
            body={permissions.canAdmin
              ? 'Add a website, publish the TXT record we generate, then issue an API key for the SDK.'
              : 'An administrator has not registered a website in this workspace yet.'}
            action={permissions.canAdmin
              ? <Button variant="primary" onClick={() => navigate('/websites/new')} icon={<Plus size={14} aria-hidden="true" />}>Add website</Button>
              : undefined}
          />
        ) : (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>Website</th>
                  <th>Verification</th>
                  <th>Connection</th>
                  <th>Last event</th>
                  <th className="right">Open incidents</th>
                  <th className="right">Risk</th>
                </tr>
              </thead>
              <tbody>
                {sites.map((site) => (
                  <tr key={site.id} className="row-link" onClick={() => navigate(`/websites/${site.id}`)}>
                    <td>
                      <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
                        <Link to={`/websites/${site.id}`} className="strong small" onClick={(event) => event.stopPropagation()}>
                          {site.displayName}
                        </Link>
                        {isTestDomain(site.hostname) && <Badge tone="purple">test domain</Badge>}
                      </div>
                      <div className="tiny faint mono" title={`${site.scheme}://${site.hostname}`}>
                        {site.scheme}://{site.hostname}
                        {site.hostnameUnicode !== site.hostname ? ` (${site.hostnameUnicode})` : ''}
                      </div>
                    </td>
                    <td><Badge tone={SITE_STATUS_TONE[site.status] as Tone} dot>{STATUS_LABEL[site.status as SiteStatus]}</Badge></td>
                    <td><Badge tone={CONNECTION_TONE[site.connection.state] as Tone} dot>{site.connection.label}</Badge></td>
                    <td className="tiny muted" title={site.lastEventAt ? formatDate(site.lastEventAt) : 'No event yet'}>
                      {site.lastEventAt ? timeAgo(site.lastEventAt) : 'No event yet'}
                    </td>
                    <td className="right">{site.openIncidents ?? 0}</td>
                    <td className="right">{site.riskScore ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}
