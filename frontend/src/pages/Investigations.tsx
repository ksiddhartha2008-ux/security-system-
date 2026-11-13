import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, Microscope, Plus } from 'lucide-react';
import { PageHeader } from '../components/layout';
import {
  Badge, Button, Card, EmptyState, ErrorState, Field, KeyValue, Modal, Pagination, SearchInput,
  SeverityBadge, StatusBadge, TableSkeleton, useToast,
} from '../components/ui';
import { useApi, useDebounced } from '../lib/hooks';
import { api, ApiError } from '../lib/api';
import { formatDate, timeAgo } from '../lib/format';
import { useAuth } from '../lib/auth';

type Investigation = {
  id: string; ref: string; title: string; hypothesis: string; status: string; severity: string;
  owner: string | null; incidentId: string | null; incidentRef: string | null; findings: string;
  createdAt: string; noteCount?: number;
};
type ListPayload = { data: Investigation[]; meta: { page: number; limit: number; total: number; totalPages: number } };

export function InvestigationsPage() {
  const { permissions } = useAuth();
  const [page, setPage] = useState(1);
  const [query, setQuery] = useState('');
  const [createOpen, setCreateOpen] = useState(false);
  const debounced = useDebounced(query, 300);
  const params = new URLSearchParams({ page: String(page), limit: '20' });
  if (debounced.trim()) params.set('q', debounced.trim());
  const investigations = useApi<ListPayload>(`/investigations?${params.toString()}`);

  return (
    <>
      <PageHeader title="Investigations" subtitle="Structured analysis: a hypothesis, the evidence you checked, and a conclusion that outlives the shift."
        actions={permissions.canWrite ? <Button variant="primary" icon={<Plus size={14} aria-hidden="true" />} onClick={() => setCreateOpen(true)}>New investigation</Button> : undefined} />

      <Card bodyClass="">
        <div className="card-head">
          <SearchInput value={query} onChange={(v) => { setQuery(v); setPage(1); }} placeholder="Search investigations" label="Search investigations" />
          <span className="tiny faint" style={{ marginLeft: 'auto' }}>{investigations.data?.meta.total ?? 0} open case files</span>
        </div>
        {investigations.loading && !investigations.data ? <TableSkeleton rows={5} cols={5} /> : investigations.error ? <ErrorState message={investigations.error} onRetry={investigations.refresh} /> : (
          <>
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>Reference</th><th>Investigation</th><th>Severity</th><th>Status</th><th>Incident</th><th>Notes</th><th className="right">Opened</th></tr></thead>
                <tbody>
                  {investigations.data?.data.map((inv) => (
                    <tr key={inv.id}>
                      <td className="mono tiny"><Link to={`/investigations/${inv.id}`} style={{ color: 'var(--color-mint-bright)' }}>{inv.ref}</Link></td>
                      <td>
                        <Link to={`/investigations/${inv.id}`} style={{ fontWeight: 550 }}>{inv.title}</Link>
                        <p className="tiny faint truncate-cell" style={{ maxWidth: 420 }}>{inv.hypothesis}</p>
                      </td>
                      <td><SeverityBadge severity={inv.severity} /></td>
                      <td><StatusBadge status={inv.status} /></td>
                      <td className="mono tiny muted">{inv.incidentRef ?? '—'}</td>
                      <td className="small muted">{inv.noteCount ?? 0}</td>
                      <td className="right tiny faint">{timeAgo(inv.createdAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {investigations.data?.data.length === 0 && <EmptyState title="No investigations yet" body="Open one from an incident, or start a case file for something that does not have an incident yet." icon={<Microscope size={18} aria-hidden="true" />} />}
            {investigations.data && investigations.data.data.length > 0 && (
              <Pagination page={investigations.data.meta.page} totalPages={investigations.data.meta.totalPages} total={investigations.data.meta.total} onPage={setPage} />
            )}
          </>
        )}
      </Card>
      <CreateInvestigationModal open={createOpen} onClose={() => setCreateOpen(false)} onCreated={() => investigations.refresh()} />
    </>
  );
}

function CreateInvestigationModal({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: () => void }) {
  const toast = useToast();
  const navigate = useNavigate();
  const incidents = useApi<{ data: { id: string; ref: string; title: string }[] }>('/incidents?limit=100');
  const [form, setForm] = useState({ title: '', hypothesis: '', severity: 'medium', incidentId: '' });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setError(null);
    if (form.title.trim().length < 4) { setError('Give the investigation a specific title'); return; }
    setBusy(true);
    try {
      const result = await api.post<{ id: string }>('/investigations', {
        title: form.title.trim(), hypothesis: form.hypothesis.trim(), severity: form.severity,
        incidentId: form.incidentId || null,
      });
      toast.push('success', 'Investigation opened');
      onCreated(); onClose();
      navigate(`/investigations/${result.id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not open the investigation');
    } finally { setBusy(false); }
  };

  return (
    <Modal open={open} onClose={onClose} title="New investigation" subtitle="State what you think happened, then test it against telemetry."
      footer={<><Button variant="ghost" onClick={onClose} type="button">Cancel</Button><Button variant="primary" onClick={submit} loading={busy} type="button">Open investigation</Button></>}>
      {error && <div className="error-box" role="alert">{error}</div>}
      <Field label="Title" htmlFor="inv-title" required>
        <input id="inv-title" className="input" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} placeholder="How did the loader reach ws-fin-114?" />
      </Field>
      <Field label="Hypothesis" htmlFor="inv-hyp" hint="A sentence you can prove or disprove.">
        <textarea id="inv-hyp" className="textarea" value={form.hypothesis} onChange={(e) => setForm({ ...form, hypothesis: e.target.value })} placeholder="The loader arrived through a signed installer opened from an invoice attachment." />
      </Field>
      <div className="grid grid-2">
        <Field label="Severity" htmlFor="inv-sev">
          <select id="inv-sev" className="select" value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
            {['critical', 'high', 'medium', 'low'].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </Field>
        <Field label="Linked incident" htmlFor="inv-inc">
          <select id="inv-inc" className="select" value={form.incidentId} onChange={(e) => setForm({ ...form, incidentId: e.target.value })}>
            <option value="">None</option>
            {(incidents.data?.data ?? []).map((incident) => <option key={incident.id} value={incident.id}>{incident.ref} · {incident.title}</option>)}
          </select>
        </Field>
      </div>
    </Modal>
  );
}

type Detail = Investigation & {
  owner: string | null;
  notes: { id: string; body: string; author: string | null; createdAt: string }[];
  iocs: { id: string; type: string; value: string; threat_type: string; confidence: number; status: string }[];
  incidents: { id: string; ref: string; title: string; severity: string; status: string; detected_at: string }[];
  assets: { id: string; name: string; hostname: string; risk_score: number; criticality: string }[];
  timeline: { at: string; kind: string; label: string; detail: string }[];
};

export function InvestigationDetailPage() {
  const { id } = useParams();
  const { permissions } = useAuth();
  const toast = useToast();
  const navigate = useNavigate();
  const investigation = useApi<Detail>(id ? `/investigations/${id}` : null);
  const [note, setNote] = useState('');
  const [findings, setFindings] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (investigation.loading) return <Card><TableSkeleton rows={8} cols={3} /></Card>;
  if (investigation.error) return <Card><ErrorState message={investigation.error} onRetry={investigation.refresh} /></Card>;
  if (!investigation.data) return null;
  const data = investigation.data;

  const addNote = async () => {
    if (note.trim().length < 2) return;
    setBusy(true);
    try {
      await api.post(`/investigations/${data.id}/notes`, { body: note.trim() });
      setNote(''); investigation.refresh(); toast.push('success', 'Note recorded');
    } catch (err) { toast.push('error', 'Could not record the note', err instanceof ApiError ? err.message : undefined); }
    finally { setBusy(false); }
  };

  const saveFindings = async () => {
    try {
      await api.patch(`/investigations/${data.id}`, { findings: findings ?? data.findings });
      setFindings(null); investigation.refresh(); toast.push('success', 'Findings saved');
    } catch (err) { toast.push('error', 'Could not save findings', err instanceof ApiError ? err.message : undefined); }
  };

  return (
    <>
      <div className="row" style={{ marginBottom: 12 }}>
        <Button size="sm" variant="ghost" onClick={() => navigate('/investigations')} icon={<ArrowLeft size={14} aria-hidden="true" />}>Investigations</Button>
        <span className="mono tiny faint">{data.ref}</span>
      </div>
      <div className="page-head">
        <div>
          <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}><SeverityBadge severity={data.severity} /><StatusBadge status={data.status} /><Badge tone="neutral">{data.owner ?? 'Unassigned'}</Badge></div>
          <h1 className="page-title" style={{ marginTop: 8 }}>{data.title}</h1>
          <p className="page-sub">Opened {formatDate(data.createdAt)}</p>
        </div>
        {permissions.canWrite && (
          <div className="page-actions">
            {['active', 'paused', 'concluded'].filter((s) => s !== data.status).map((status) => (
              <Button key={status} size="sm" variant={status === 'concluded' ? 'primary' : 'default'} onClick={async () => {
                try { await api.patch(`/investigations/${data.id}`, { status }); toast.push('success', `Marked ${status}`); investigation.refresh(); }
                catch (err) { toast.push('error', 'Update failed'); }
              }}>Mark {status}</Button>
            ))}
          </div>
        )}
      </div>

      <div className="grid" style={{ gridTemplateColumns: '1.45fr 1fr' }}>
        <div className="stack">
          <Card title="Hypothesis" subtitle="The claim under test">
            <p className="small" style={{ color: 'var(--color-ink-soft)' }}>{data.hypothesis || 'No hypothesis recorded.'}</p>
          </Card>

          <Card title="Correlated timeline" subtitle="High severity telemetry and analyst notes, oldest first">
            {data.timeline.length === 0 ? <p className="small faint">Nothing correlated yet.</p> : (
              <div className="timeline">
                {data.timeline.map((entry, index) => (
                  <div key={`${entry.at}-${index}`} className={`timeline-item ${entry.kind}`}>
                    <p className="timeline-time">{formatDate(entry.at)} · {entry.kind}</p>
                    <p className="timeline-body strong">{entry.label}</p>
                    <p className="tiny muted">{entry.detail}</p>
                  </div>
                ))}
              </div>
            )}
          </Card>

          <Card title="Analyst notes" subtitle={`${data.notes.length} notes`}>
            {permissions.canWrite && (
              <div style={{ marginBottom: 14 }}>
                <Field label="New note" htmlFor="inv-note">
                  <textarea id="inv-note" className="textarea" value={note} onChange={(e) => setNote(e.target.value)} placeholder="What you checked and what it showed." />
                </Field>
                <div className="row" style={{ justifyContent: 'flex-end', marginTop: 8 }}>
                  <Button size="sm" variant="primary" onClick={addNote} loading={busy} disabled={note.trim().length < 2}>Record note</Button>
                </div>
              </div>
            )}
            {data.notes.length === 0 ? <p className="small faint">No notes yet.</p> : (
              <div className="stack" style={{ gap: 10 }}>
                {data.notes.map((entry) => (
                  <div key={entry.id} style={{ borderLeft: '2px solid var(--color-timeline-dot)', paddingLeft: 10 }}>
                    <p className="tiny faint">{entry.author ?? 'Analyst'} · {formatDate(entry.createdAt)}</p>
                    <p className="small" style={{ color: 'var(--color-ink-soft)', whiteSpace: 'pre-wrap' }}>{entry.body}</p>
                  </div>
                ))}
              </div>
            )}
          </Card>

          <Card title="Findings" subtitle="The conclusion that survives the shift">
            {permissions.canWrite ? (
              <>
                <textarea className="textarea" value={findings ?? data.findings} onChange={(e) => setFindings(e.target.value)}
                  placeholder="What did the evidence show? State what is confirmed, what is not, and what remains open." />
                <div className="row" style={{ justifyContent: 'flex-end', marginTop: 8 }}>
                  <Button size="sm" variant="primary" onClick={saveFindings} disabled={findings === null}>Save findings</Button>
                </div>
              </>
            ) : <p className="small" style={{ whiteSpace: 'pre-wrap' }}>{data.findings || 'No findings recorded.'}</p>}
          </Card>
        </div>

        <div className="stack">
          <Card title="Case facts">
            <KeyValue items={[
              { label: 'Reference', value: <span className="mono">{data.ref}</span> },
              { label: 'Owner', value: data.owner ?? 'Unassigned' },
              { label: 'Status', value: <StatusBadge status={data.status} /> },
              { label: 'Linked incident', value: data.incidentRef ?? 'None' },
              { label: 'Notes', value: String(data.notes.length) },
            ]} />
          </Card>

          <Card title="Indicators to check" subtitle="Workspace indicator inventory">
            {data.iocs.length === 0 ? <p className="small faint">No indicators stored.</p> : (
              <div className="stack" style={{ gap: 7 }}>
                {data.iocs.slice(0, 8).map((ioc) => (
                  <div key={ioc.id} className="row" style={{ gap: 8 }}>
                    <Badge tone="neutral">{ioc.type}</Badge>
                    <span className="mono tiny truncate-cell" style={{ flex: 1 }}>{ioc.value}</span>
                    <span className="tiny faint">{ioc.confidence}</span>
                  </div>
                ))}
              </div>
            )}
            <div style={{ marginTop: 10 }}><Link className="btn btn-sm" to="/threat-intel">Open threat intelligence</Link></div>
          </Card>

          <Card title="Assets in scope" subtitle="Highest risk in the last 14 days">
            {data.assets.length === 0 ? <p className="small faint">No assets correlated.</p> : (
              <div className="stack" style={{ gap: 8 }}>
                {data.assets.map((asset) => (
                  <div key={asset.id} className="row" style={{ gap: 8 }}>
                    <span className="mono tiny muted">{asset.hostname}</span>
                    <span className="small truncate-cell" style={{ flex: 1 }}>{asset.name}</span>
                    <Badge tone={asset.risk_score >= 70 ? 'high' : 'neutral'}>{asset.risk_score}</Badge>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>
    </>
  );
}
