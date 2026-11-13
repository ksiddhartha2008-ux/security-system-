import { useMemo, useState } from 'react';
import { Activity, Download, Plus, Radio } from 'lucide-react';
import { PageHeader } from '../components/layout';
import {
  Badge, Button, Card, Drawer, EmptyState, ErrorState, Field, Modal, Pagination, SearchInput,
  SeverityBadge, StatusBadge, TableSkeleton, useToast, OriginBadge,
} from '../components/ui';
import { useApi, useDebounced, useEventStream } from '../lib/hooks';
import { api, ApiError } from '../lib/api';
import { formatDate, timeAgo } from '../lib/format';
import { useAuth } from '../lib/auth';

type EventRow = { dataOrigin?: string;
  id: string; eventType: string; source: string; severity: string; category: string; title: string;
  description: string | null; srcIp: string | null; destIp: string | null; userEmail: string | null;
  assetId: string | null; assetHostname: string | null; status: string; occurredAt: string;
};
type EventsPayload = { data: EventRow[]; meta: { page: number; limit: number; total: number; totalPages: number } };
type EventDetail = EventRow & {
  raw: Record<string, unknown>;
  detections: { id: string; title: string; severity: string; risk_score: number; status: string }[];
  related: { id: string; title: string; severity: string; occurred_at: string }[];
};
type Facets = { severities: Record<string, number>; sources: { source: string; count: number }[]; categories: { category: string; count: number }[] };

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const CATEGORIES = ['identity', 'endpoint', 'network', 'application', 'email', 'vulnerability', 'cloud'];

export default function MonitoringPage() {
  const { permissions } = useAuth();
  const toast = useToast();
  const [page, setPage] = useState(1);
  const [severity, setSeverity] = useState('');
  const [category, setCategory] = useState('');
  const [query, setQuery] = useState('');
  const debounced = useDebounced(query, 300);
  const [selected, setSelected] = useState<string | null>(null);
  const [ingestOpen, setIngestOpen] = useState(false);
  const [liveCount, setLiveCount] = useState(0);

  const params = new URLSearchParams({ page: String(page), limit: '25' });
  if (severity) params.set('severity', severity);
  if (category) params.set('category', category);
  if (debounced.trim()) params.set('q', debounced.trim());
  const path = `/events?${params.toString()}`;

  const events = useApi<EventsPayload>(path);
  const facets = useApi<Facets>('/events/facets');
  const detail = useApi<EventDetail>(selected ? `/events/${selected}` : null);

  const connected = useEventStream((event) => {
    if (event === 'event.ingested') {
      setLiveCount((c) => c + 1);
      events.refresh();
      facets.refresh();
    }
  });

  const severityCounts = facets.data?.severities ?? {};
  const total = useMemo(() => Object.values(severityCounts).reduce((a, b) => a + b, 0), [severityCounts]);

  return (
    <>
      <PageHeader
        title="Live monitoring"
        subtitle="Normalised telemetry from identity, endpoint, email, network and application sources. Newest first."
        actions={<>
          <span className={`chip`} title={connected ? 'Server sent events connected' : 'Falling back to manual refresh'}>
            <Radio size={12} aria-hidden="true" color={connected ? 'var(--color-mint)' : 'var(--color-faint)'} />
            {connected ? 'Streaming' : 'Reconnecting'}
          </span>
          <Button icon={<Download size={14} aria-hidden="true" />} onClick={() => events.refresh()}>Refresh</Button>
          {permissions.canWrite && <Button variant="primary" icon={<Plus size={14} aria-hidden="true" />} onClick={() => setIngestOpen(true)}>Ingest event</Button>}
        </>}
      />

      <div className="grid grid-4" style={{ marginBottom: 14 }}>
        {SEVERITIES.slice(0, 4).map((sev) => (
          <button key={sev} type="button" onClick={() => { setSeverity(severity === sev ? '' : sev); setPage(1); }}
            className="card kpi" style={{ textAlign: 'left', cursor: 'pointer', borderColor: severity === sev ? 'rgba(61,220,151,0.45)' : undefined }}>
            <div className="kpi-label"><SeverityBadge severity={sev} /></div>
            <div className="kpi-value">{severityCounts[sev] ?? 0}</div>
            <div className="kpi-foot">{total ? Math.round(((severityCounts[sev] ?? 0) / total) * 100) : 0}% of all events</div>
          </button>
        ))}
      </div>

      <Card bodyClass="">
        <div className="card-head" style={{ flexWrap: 'wrap', gap: 10 }}>
          <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
            <SearchInput value={query} onChange={(v) => { setQuery(v); setPage(1); }} placeholder="Search title, IP, user or type" label="Search events" />
            <select className="select" style={{ width: 150 }} value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }} aria-label="Filter by severity">
              <option value="">All severities</option>
              {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <select className="select" style={{ width: 160 }} value={category} onChange={(e) => { setCategory(e.target.value); setPage(1); }} aria-label="Filter by category">
              <option value="">All categories</option>
              {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
            {(severity || category || query) && <Button size="sm" variant="ghost" onClick={() => { setSeverity(''); setCategory(''); setQuery(''); setPage(1); }}>Clear</Button>}
          </div>
          <div className="row" style={{ marginLeft: 'auto', gap: 8 }}>
            {liveCount > 0 && <Badge tone="mint">{liveCount} new</Badge>}
            <span className="tiny faint">{events.data?.meta.total ?? 0} matching</span>
          </div>
        </div>

        {events.loading && !events.data ? <TableSkeleton rows={8} cols={5} /> : events.error ? <ErrorState message={events.error} onRetry={events.refresh} /> : (
          <>
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr><th>Severity</th><th>Event</th><th>Source</th><th>Endpoints</th><th>Asset</th><th>Status</th><th className="right">Occurred</th></tr>
                </thead>
                <tbody>
                  {events.data?.data.map((event) => (
                    <tr key={event.id} className="row-link" onClick={() => setSelected(event.id)} tabIndex={0}
                      onKeyDown={(e) => { if (e.key === 'Enter') setSelected(event.id); }}
                      aria-label={`Open event ${event.title}`}>
                      <td><SeverityBadge severity={event.severity} /></td>
                      <td>
                        <p className="truncate-cell" style={{ maxWidth: 320 }}>{event.title}</p>
                        <p className="tiny faint mono">{event.eventType}</p>
                        <OriginBadge origin={event.dataOrigin} />
                      </td>
                      <td className="small muted">{event.source}</td>
                      <td className="mono muted tiny">{event.srcIp ?? '—'}{event.destIp ? ` → ${event.destIp}` : ''}</td>
                      <td className="mono muted tiny">{event.assetHostname ?? '—'}</td>
                      <td><StatusBadge status={event.status} /></td>
                      <td className="right tiny faint" title={formatDate(event.occurredAt)}>{timeAgo(event.occurredAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {events.data && events.data.data.length === 0 && (
              <EmptyState title="No events match these filters" body="Clear the filters or ingest a new event to see it appear here in real time." icon={<Activity size={18} aria-hidden="true" />} />
            )}
            {events.data && events.data.data.length > 0 && (
              <Pagination page={events.data.meta.page} totalPages={events.data.meta.totalPages} total={events.data.meta.total} onPage={setPage} />
            )}
          </>
        )}
      </Card>

      <Drawer open={Boolean(selected)} onClose={() => setSelected(null)} title={detail.data?.title ?? 'Event detail'}
        subtitle={detail.data ? `${detail.data.eventType} · ${detail.data.source}` : undefined}
        footer={detail.data && permissions.canWrite ? (
          <div className="row" style={{ marginLeft: 'auto' }}>
            <Button size="sm" onClick={async () => { await api.patch(`/events/${detail.data!.id}`, { status: 'triaged' }); toast.push('success', 'Marked as triaged'); detail.refresh(); events.refresh(); }}>Mark triaged</Button>
            <Button size="sm" variant="ghost" onClick={async () => { await api.patch(`/events/${detail.data!.id}`, { status: 'closed' }); toast.push('success', 'Event closed'); detail.refresh(); events.refresh(); }}>Close event</Button>
          </div>
        ) : undefined}>
        {detail.loading && <TableSkeleton rows={5} cols={2} />}
        {detail.error && <ErrorState message={detail.error} onRetry={detail.refresh} />}
        {detail.data && (
          <>
            <div className="row wrap" style={{ gap: 8 }}>
              <SeverityBadge severity={detail.data.severity} />
              <StatusBadge status={detail.data.status} />
              <Badge tone="neutral">{detail.data.category}</Badge>
            </div>
            <dl className="kv">
              <dt>Event type</dt><dd className="mono">{detail.data.eventType}</dd>
              <dt>Occurred</dt><dd>{formatDate(detail.data.occurredAt)}</dd>
              <dt>Source address</dt><dd className="mono">{detail.data.srcIp ?? '—'}</dd>
              <dt>Destination</dt><dd className="mono">{detail.data.destIp ?? '—'}</dd>
              <dt>Account</dt><dd>{detail.data.userEmail ?? '—'}</dd>
              <dt>Asset</dt><dd className="mono">{detail.data.assetHostname ?? '—'}</dd>
            </dl>
            {detail.data.description && <p className="small muted">{detail.data.description}</p>}
            <div>
              <p className="label" style={{ marginBottom: 6 }}>Raw payload</p>
              <pre className="code-block">{JSON.stringify(detail.data.raw, null, 2)}</pre>
            </div>
            <div>
              <p className="label" style={{ marginBottom: 6 }}>Detections from this event ({detail.data.detections.length})</p>
              {detail.data.detections.length === 0 ? <p className="small faint">No detection rule matched this event.</p> : detail.data.detections.map((d) => (
                <div key={d.id} className="row" style={{ padding: '6px 0', gap: 8 }}>
                  <SeverityBadge severity={d.severity} />
                  <span className="small" style={{ flex: 1 }}>{d.title}</span>
                  <Badge tone="neutral">{d.risk_score}</Badge>
                </div>
              ))}
            </div>
            <div>
              <p className="label" style={{ marginBottom: 6 }}>Related events</p>
              {detail.data.related.length === 0 ? <p className="small faint">Nothing else shares this source or asset.</p> : (
                <div className="stack" style={{ gap: 6 }}>
                  {detail.data.related.map((r) => (
                    <div key={r.id} className="row small" style={{ gap: 8 }}>
                      <SeverityBadge severity={r.severity} />
                      <span style={{ flex: 1 }} className="truncate-cell">{r.title}</span>
                      <span className="tiny faint">{timeAgo(r.occurred_at)}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </>
        )}
      </Drawer>

      <IngestModal open={ingestOpen} onClose={() => setIngestOpen(false)} onDone={() => { events.refresh(); facets.refresh(); }} />
    </>
  );
}

function IngestModal({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const assets = useApi<{ data: { id: string; hostname: string }[] }>('/assets?limit=100');
  const [form, setForm] = useState({
    eventType: 'auth.failure', source: 'identity-provider', severity: 'medium', category: 'identity',
    title: '', description: '', srcIp: '', userEmail: '', assetId: '',
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  const submit = async () => {
    setError(null);
    setFieldErrors({});
    if (form.title.trim().length < 3) { setFieldErrors({ title: 'Give the event a descriptive title' }); return; }
    if (!/^[a-z0-9._-]{3,60}$/.test(form.eventType)) { setFieldErrors({ eventType: 'Use lowercase letters, digits, dots or dashes' }); return; }
    setBusy(true);
    try {
      const result = await api.post<{ detections: { title: string }[] }>('/events', {
        eventType: form.eventType, source: form.source, severity: form.severity, category: form.category,
        title: form.title.trim(), description: form.description.trim() || undefined,
        srcIp: form.srcIp.trim() || undefined, userEmail: form.userEmail.trim() || undefined,
        assetId: form.assetId || undefined,
      });
      toast.push('success', 'Event ingested', result.detections.length ? `${result.detections.length} detection rule(s) fired.` : 'No detection rule matched.');
      onDone();
      onClose();
      setForm({ ...form, title: '', description: '', srcIp: '', userEmail: '' });
    } catch (err) {
      if (err instanceof ApiError) { setError(err.message); if (err.details) setFieldErrors(Object.fromEntries(err.details.map((d) => [d.path, d.message]))); }
      else setError('Could not ingest the event');
    } finally { setBusy(false); }
  };

  return (
    <Modal open={open} onClose={onClose} title="Ingest a security event" subtitle="The event is validated, stored in your workspace and evaluated against enabled rules."
      footer={<><Button variant="ghost" onClick={onClose} type="button">Cancel</Button><Button variant="primary" onClick={submit} loading={busy} type="button">Ingest event</Button></>}>
      {error && <div className="error-box" role="alert">{error}</div>}
      <div className="grid grid-2">
        <Field label="Event type" htmlFor="eventType" error={fieldErrors.eventType} hint="For example auth.failure">
          <input id="eventType" className="input mono" value={form.eventType} onChange={(e) => setForm({ ...form, eventType: e.target.value })} />
        </Field>
        <Field label="Source" htmlFor="source">
          <input id="source" className="input" value={form.source} onChange={(e) => setForm({ ...form, source: e.target.value })} />
        </Field>
        <Field label="Severity" htmlFor="severity">
          <select id="severity" className="select" value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </Field>
        <Field label="Category" htmlFor="category">
          <select id="category" className="select" value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })}>
            {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </Field>
      </div>
      <Field label="Title" htmlFor="title" error={fieldErrors.title} required>
        <input id="title" className="input" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} placeholder="Failed sign-in for j.reyes" />
      </Field>
      <Field label="Description" htmlFor="description">
        <textarea id="description" className="textarea" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder="Context an analyst would need on first read" />
      </Field>
      <div className="grid grid-2">
        <Field label="Source IP" htmlFor="srcIp"><input id="srcIp" className="input mono" value={form.srcIp} onChange={(e) => setForm({ ...form, srcIp: e.target.value })} placeholder="203.0.113.10" /></Field>
        <Field label="Account" htmlFor="userEmail"><input id="userEmail" className="input" value={form.userEmail} onChange={(e) => setForm({ ...form, userEmail: e.target.value })} placeholder="user@company.com" /></Field>
      </div>
      <Field label="Asset" htmlFor="assetId" hint="Optional. Attach the event to an asset so risk scoring can use its criticality.">
        <select id="assetId" className="select" value={form.assetId} onChange={(e) => setForm({ ...form, assetId: e.target.value })}>
          <option value="">No asset</option>
          {(assets.data?.data ?? []).map((asset) => <option key={asset.id} value={asset.id}>{asset.hostname}</option>)}
        </select>
      </Field>
    </Modal>
  );
}
