import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, Plus, Siren } from 'lucide-react';
import { PageHeader } from '../components/layout';
import { MetricCard } from '../components/design';
import {
  Badge, Button, Card, ConfirmDialog, EmptyState, ErrorState, Field, KeyValue, Modal, Pagination, SearchInput,
  SeverityBadge, StatusBadge, TableSkeleton, Tabs, useToast, OriginBadge,
} from '../components/ui';
import { useApi, useDebounced } from '../lib/hooks';
import { api, ApiError } from '../lib/api';
import { formatDate, timeAgo } from '../lib/format';
import { useAuth } from '../lib/auth';

type Incident = { dataOrigin?: string;
  id: string; ref: string; title: string; description: string; severity: string; priority: string; status: string;
  assigneeId: string | null; assignee: string | null; detectedAt: string; dueAt: string | null; resolvedAt: string | null; createdAt: string;
};
type ListPayload = { data: Incident[]; meta: { page: number; limit: number; total: number; totalPages: number; counts: Record<string, number> } };
type UserRow = { id: string; name: string; role: string; email: string };

const STATUSES = ['open', 'investigating', 'contained', 'resolved', 'closed'];

export function IncidentsPage() {
  const { permissions } = useAuth();
  const [tab, setTab] = useState<'all' | string>('all');
  const [page, setPage] = useState(1);
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('');
  const [createOpen, setCreateOpen] = useState(false);
  const debounced = useDebounced(query, 300);

  const params = new URLSearchParams({ page: String(page), limit: '20' });
  if (tab !== 'all') params.set('status', tab);
  if (severity) params.set('severity', severity);
  if (debounced.trim()) params.set('q', debounced.trim());

  const incidents = useApi<ListPayload>(`/incidents?${params.toString()}`);
  const counts = incidents.data?.meta.counts ?? {};
  const total = Object.values(counts).reduce((a, b) => a + b, 0);

  return (
    <>
      <PageHeader title="Incident response" subtitle="A single queue for every confirmed or suspected security event, with a lifecycle you can audit."
        actions={permissions.canWrite ? <Button variant="primary" icon={<Plus size={14} aria-hidden="true" />} onClick={() => setCreateOpen(true)}>Open incident</Button> : undefined} />

      <div className="grid grid-4" style={{ marginBottom: 14 }}>
        <MetricCard label="Open queue" value={(counts.open ?? 0) + (counts.investigating ?? 0) + (counts.contained ?? 0)} foot="Across open, investigating and contained" />
        <MetricCard label="Investigating" value={counts.investigating ?? 0} foot="Owner assigned and work in progress" />
        <MetricCard label="Contained" value={counts.contained ?? 0} foot="Exposure stopped, closure pending" />
        <MetricCard label="Resolved" value={(counts.resolved ?? 0) + (counts.closed ?? 0)} foot={`Of ${total} recorded incidents`} />
      </div>

      <Card bodyClass="">
        <div style={{ padding: '0 16px' }}>
          <Tabs
            active={tab}
            onChange={(key) => { setTab(key); setPage(1); }}
            label="Incident status"
            tabs={[{ key: 'all', label: 'All', count: total }, ...STATUSES.map((s) => ({ key: s, label: s[0].toUpperCase() + s.slice(1), count: counts[s] ?? 0 }))]}
          />
        </div>
        <div className="card-head" style={{ borderTop: 'none', flexWrap: 'wrap', gap: 10 }}>
          <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
            <SearchInput value={query} onChange={(v) => { setQuery(v); setPage(1); }} placeholder="Search reference, title or description" label="Search incidents" />
            <select className="select" style={{ width: 150 }} value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }} aria-label="Filter by severity">
              <option value="">Any severity</option>
              {['critical', 'high', 'medium', 'low'].map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <span className="tiny faint" style={{ marginLeft: 'auto' }}>{incidents.data?.meta.total ?? 0} incidents</span>
        </div>

        {incidents.loading && !incidents.data ? <TableSkeleton rows={7} cols={6} /> : incidents.error ? <ErrorState message={incidents.error} onRetry={incidents.refresh} /> : (
          <>
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>Reference</th><th>Incident</th><th>Severity</th><th>Priority</th><th>Status</th><th>Owner</th><th className="right">Detected</th></tr></thead>
                <tbody>
                  {incidents.data?.data.map((incident) => (
                    <tr key={incident.id}>
                      <td className="mono tiny"><Link to={`/incidents/${incident.id}`} style={{ color: 'var(--color-mint-bright)' }}>{incident.ref}</Link></td>
                      <td>
                        <Link to={`/incidents/${incident.id}`} style={{ fontWeight: 550 }} className="truncate-cell" >{incident.title}</Link>
                        <p className="tiny faint">{incident.description.slice(0, 90)}{incident.description.length > 90 ? '…' : ''}</p>
                        <OriginBadge origin={incident.dataOrigin} />
                      </td>
                      <td><SeverityBadge severity={incident.severity} /></td>
                      <td className="mono tiny">{incident.priority}</td>
                      <td><StatusBadge status={incident.status} /></td>
                      <td className="small muted">{incident.assignee ?? 'Unassigned'}</td>
                      <td className="right tiny faint" title={formatDate(incident.detectedAt)}>{timeAgo(incident.detectedAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {incidents.data?.data.length === 0 && <EmptyState title="No incidents here" body="Open one manually, or promote a detection from the detection queue." icon={<Siren size={18} aria-hidden="true" />} />}
            {incidents.data && incidents.data.data.length > 0 && (
              <Pagination page={incidents.data.meta.page} totalPages={incidents.data.meta.totalPages} total={incidents.data.meta.total} onPage={setPage} />
            )}
          </>
        )}
      </Card>

      <CreateIncidentModal open={createOpen} onClose={() => setCreateOpen(false)} onCreated={() => { incidents.refresh(); }} />
    </>
  );
}

function CreateIncidentModal({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: () => void }) {
  const toast = useToast();
  const navigate = useNavigate();
  const users = useApi<UserRow[]>('/settings/users');
  const [form, setForm] = useState({ title: '', description: '', severity: 'high', priority: 'P2', assigneeId: '' });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setError(null); setErrors({});
    if (form.title.trim().length < 4) { setErrors({ title: 'Describe the incident in at least four characters' }); return; }
    setBusy(true);
    try {
      const result = await api.post<{ id: string; ref: string }>('/incidents', {
        title: form.title.trim(), description: form.description.trim(), severity: form.severity,
        priority: form.priority, assigneeId: form.assigneeId || null,
      });
      toast.push('success', `Incident ${result.ref} opened`);
      onCreated(); onClose();
      navigate(`/incidents/${result.id}`);
    } catch (err) {
      if (err instanceof ApiError) { setError(err.message); if (err.details) setErrors(Object.fromEntries(err.details.map((d) => [d.path, d.message]))); }
      else setError('Could not open the incident');
    } finally { setBusy(false); }
  };

  return (
    <Modal open={open} onClose={onClose} title="Open an incident" subtitle="Use this when the work needs an owner, a timeline and a resolution record."
      footer={<><Button variant="ghost" onClick={onClose} type="button">Cancel</Button><Button variant="primary" onClick={submit} loading={busy} type="button">Open incident</Button></>}>
      {error && <div className="error-box" role="alert">{error}</div>}
      <Field label="Title" htmlFor="i-title" error={errors.title} required>
        <input id="i-title" className="input" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} placeholder="Suspicious sign-in burst from a new address range" />
      </Field>
      <Field label="What happened" htmlFor="i-desc">
        <textarea id="i-desc" className="textarea" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder="Facts an analyst needs at handover: what was observed, what is affected, what has already been tried." />
      </Field>
      <div className="grid grid-2">
        <Field label="Severity" htmlFor="i-sev">
          <select id="i-sev" className="select" value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
            {['critical', 'high', 'medium', 'low'].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </Field>
        <Field label="Priority" htmlFor="i-pri">
          <select id="i-pri" className="select" value={form.priority} onChange={(e) => setForm({ ...form, priority: e.target.value })}>
            {['P1', 'P2', 'P3', 'P4'].map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
        </Field>
      </div>
      <Field label="Owner" htmlFor="i-owner">
        <select id="i-owner" className="select" value={form.assigneeId} onChange={(e) => setForm({ ...form, assigneeId: e.target.value })}>
          <option value="">Unassigned</option>
          {(users.data ?? []).map((user) => <option key={user.id} value={user.id}>{user.name} · {user.role}</option>)}
        </select>
      </Field>
    </Modal>
  );
}

/* ------------------------------ detail ------------------------------ */

type Detail = Incident & {
  assigneeEmail: string | null;
  timeline: { id: string; type: string; message: string; actor: string | null; metadata: Record<string, unknown>; createdAt: string }[];
  detections: { id: string; title: string; severity: string; risk_score: number; status: string; detected_at: string }[];
  investigations: { id: string; ref: string; title: string; status: string }[];
  allowedTransitions: string[];
};

export function IncidentDetailPage() {
  const { id } = useParams();
  const { permissions } = useAuth();
  const toast = useToast();
  const navigate = useNavigate();
  const incident = useApi<Detail>(id ? `/incidents/${id}` : null);
  const users = useApi<UserRow[]>('/settings/users');
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [pendingStatus, setPendingStatus] = useState<string | null>(null);
  const [transitioning, setTransitioning] = useState(false);

  if (incident.loading) return <Card><TableSkeleton rows={8} cols={3} /></Card>;
  if (incident.error) return <Card><ErrorState message={incident.error} onRetry={incident.refresh} /></Card>;
  if (!incident.data) return null;
  const data = incident.data;

  const transition = async (status: string) => {
    try {
      await api.patch(`/incidents/${data.id}`, { status });
      toast.push('success', `Incident moved to ${status}`);
      incident.refresh();
    } catch (err) {
      toast.push('error', 'Transition rejected', err instanceof ApiError ? err.message : undefined);
    }
  };

  const requestTransition = (status: string) => {
    if (status === 'resolved' || status === 'closed') setPendingStatus(status);
    else transition(status);
  };

  const addNote = async () => {
    if (note.trim().length < 2) return;
    setBusy(true);
    try {
      await api.post(`/incidents/${data.id}/notes`, { message: note.trim() });
      setNote('');
      incident.refresh();
      toast.push('success', 'Note added to the timeline');
    } catch (err) {
      toast.push('error', 'Could not add the note', err instanceof ApiError ? err.message : undefined);
    } finally { setBusy(false); }
  };

  const createInvestigation = async () => {
    try {
      const result = await api.post<{ id: string }>('/investigations', {
        title: `Investigation: ${data.title}`, hypothesis: 'Document what you believe happened and test it against the telemetry.',
        severity: data.severity, incidentId: data.id,
      });
      toast.push('success', 'Investigation opened');
      navigate(`/investigations/${result.id}`);
    } catch (err) {
      toast.push('error', 'Could not open an investigation', err instanceof ApiError ? err.message : undefined);
    }
  };

  return (
    <>
      <div className="row" style={{ marginBottom: 12 }}>
        <Button size="sm" variant="ghost" onClick={() => navigate('/incidents')} icon={<ArrowLeft size={14} aria-hidden="true" />}>Incident queue</Button>
        <span className="mono tiny faint">{data.ref}</span>
      </div>

      <div className="page-head">
        <div style={{ minWidth: 0 }}>
          <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
            <SeverityBadge severity={data.severity} />
            <StatusBadge status={data.status} />
            <Badge tone="neutral">{data.priority}</Badge>
          </div>
          <h1 className="page-title" style={{ marginTop: 8 }}>{data.title}</h1>
          <p className="page-sub">Detected {formatDate(data.detectedAt)} · Owner {data.assignee ?? 'unassigned'}</p>
        </div>
        <div className="page-actions">
          {permissions.canWrite && data.allowedTransitions.map((next) => (
            <Button key={next} size="sm" variant={next === 'resolved' || next === 'closed' ? 'primary' : 'default'} onClick={() => requestTransition(next)}>
              Move to {next}
            </Button>
          ))}
        </div>
      </div>

      <div className="grid" style={{ gridTemplateColumns: '1.5fr 1fr' }}>
        <div className="stack">
          <Card title="What happened" subtitle="Recorded description">
            <p className="small" style={{ color: 'var(--color-ink-soft)', whiteSpace: 'pre-wrap' }}>{data.description || 'No description recorded.'}</p>
            <div className="divider" style={{ margin: '14px 0' }} />
            <KeyValue items={[
              { label: 'Reference', value: <span className="mono">{data.ref}</span> },
              { label: 'Detected', value: formatDate(data.detectedAt) },
              { label: 'Due', value: data.dueAt ? formatDate(data.dueAt) : '—' },
              { label: 'Resolved', value: data.resolvedAt ? formatDate(data.resolvedAt) : 'Not yet' },
            ]} />
          </Card>

          <Card title="Timeline" subtitle={`${data.timeline.length} recorded actions`}>
            <div className="timeline">
              {data.timeline.map((entry) => (
                <div key={entry.id} className={`timeline-item ${entry.type}`}>
                  <p className="timeline-time">{formatDate(entry.createdAt)} · {entry.actor ?? 'system'} · {entry.type}</p>
                  <p className="timeline-body">{entry.message}</p>
                </div>
              ))}
            </div>
            {permissions.canWrite && (
              <div style={{ marginTop: 14 }}>
                <Field label="Add a timeline note" htmlFor="note">
                  <textarea id="note" className="textarea" value={note} onChange={(e) => setNote(e.target.value)} placeholder="What you checked, what you found, what you changed." />
                </Field>
                <div className="row" style={{ marginTop: 8, justifyContent: 'flex-end' }}>
                  <Button size="sm" variant="primary" onClick={addNote} loading={busy} disabled={note.trim().length < 2}>Add note</Button>
                </div>
              </div>
            )}
          </Card>
        </div>

        <div className="stack">
          <Card title="Ownership" subtitle="Only members of this workspace can be assigned">
            {permissions.canWrite ? (
              <Field label="Assigned analyst" htmlFor="assignee">
                <select id="assignee" className="select" value={data.assigneeId ?? ''} onChange={async (e) => {
                  try {
                    await api.patch(`/incidents/${data.id}`, { assigneeId: e.target.value || null });
                    toast.push('success', 'Owner updated'); incident.refresh();
                  } catch (err) { toast.push('error', 'Could not update the owner', err instanceof ApiError ? err.message : undefined); }
                }}>
                  <option value="">Unassigned</option>
                  {(users.data ?? []).map((user) => <option key={user.id} value={user.id}>{user.name} · {user.role}</option>)}
                </select>
              </Field>
            ) : <p className="small muted">{data.assignee ?? 'Unassigned'}</p>}
            <div className="divider" style={{ margin: '14px 0' }} />
            <div className="stack" style={{ gap: 8 }}>
              <p className="tiny faint">Severity can change as the picture improves.</p>
              {permissions.canWrite && (
                <select className="select" value={data.severity} onChange={async (e) => {
                  try { await api.patch(`/incidents/${data.id}`, { severity: e.target.value }); toast.push('success', 'Severity updated'); incident.refresh(); }
                  catch (err) { toast.push('error', 'Could not update severity'); }
                }} aria-label="Incident severity">
                  {['critical', 'high', 'medium', 'low'].map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              )}
            </div>
          </Card>

          <Card title="Linked detections" subtitle="Promoted from the detection queue">
            {data.detections.length === 0 ? <p className="small faint">No detection is linked yet. Open one from the detection queue and promote it.</p> : (
              <div className="stack" style={{ gap: 10 }}>
                {data.detections.map((detection) => (
                  <div key={detection.id} className="row" style={{ gap: 8 }}>
                    <SeverityBadge severity={detection.severity} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <p className="small truncate-cell">{detection.title}</p>
                      <p className="tiny faint">Risk {detection.risk_score} · {timeAgo(detection.detected_at)}</p>
                    </div>
                    <StatusBadge status={detection.status} />
                  </div>
                ))}
              </div>
            )}
          </Card>

          <Card title="Investigations" subtitle="Deeper work attached to this incident"
            actions={permissions.canWrite ? <Button size="sm" onClick={createInvestigation}>Open one</Button> : undefined}>
            {data.investigations.length === 0 ? <p className="small faint">No investigation is linked.</p> : (
              <div className="stack" style={{ gap: 8 }}>
                {data.investigations.map((inv) => (
                  <Link key={inv.id} to={`/investigations/${inv.id}`} className="row" style={{ gap: 8 }}>
                    <span className="mono tiny muted">{inv.ref}</span>
                    <span className="small truncate-cell" style={{ flex: 1 }}>{inv.title}</span>
                    <StatusBadge status={inv.status} />
                  </Link>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>

      <ConfirmDialog
        open={pendingStatus !== null}
        title={`Move this incident to ${pendingStatus ?? ''}?`}
        body={pendingStatus === 'closed'
          ? 'Closing records the incident as finished. Add a timeline note first if the closure needs an explanation.'
          : 'Resolving records the incident as handled. The timeline keeps every earlier action.'}
        confirmLabel={pendingStatus ? `Move to ${pendingStatus}` : 'Confirm'}
        loading={transitioning}
        onClose={() => setPendingStatus(null)}
        onConfirm={async () => {
          if (!pendingStatus) return;
          setTransitioning(true);
          await transition(pendingStatus);
          setTransitioning(false);
          setPendingStatus(null);
        }}
      />
    </>
  );
}
