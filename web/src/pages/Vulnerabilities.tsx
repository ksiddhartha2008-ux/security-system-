import { useState } from 'react';
import { Plus, ShieldCheck } from 'lucide-react';
import { PageHeader } from '../components/layout';
import {
  Badge, Button, Card, Drawer, EmptyState, ErrorState, Field, KeyValue, Modal, Pagination,
  SearchInput, SeverityBadge, StatusBadge, TableSkeleton, useToast, OriginBadge,
} from '../components/ui';
import { useApi, useDebounced } from '../lib/hooks';
import { api, ApiError } from '../lib/api';
import { formatDate } from '../lib/format';
import { useAuth } from '../lib/auth';

type Vuln = { dataOrigin?: string;
  id: string; cveId: string | null; title: string; description: string; severity: string; cvss: number;
  assetId: string | null; assetName: string | null; assetHostname: string | null; status: string;
  remediation: string | null; dueAt: string | null; discoveredAt: string;
};
type ListPayload = { data: Vuln[]; meta: { page: number; limit: number; total: number; totalPages: number; counts: Record<string, number> } };
const STATUSES = ['open', 'in_progress', 'remediated', 'accepted', 'false_positive'];

export default function VulnerabilitiesPage() {
  const { permissions } = useAuth();
  const toast = useToast();
  const [page, setPage] = useState(1);
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('');
  const [createOpen, setCreateOpen] = useState(false);
  const [selected, setSelected] = useState<Vuln | null>(null);
  const debounced = useDebounced(query, 300);

  const params = new URLSearchParams({ page: String(page), limit: '20' });
  if (debounced.trim()) params.set('q', debounced.trim());
  if (severity) params.set('severity', severity);
  if (status) params.set('status', status);
  const vulns = useApi<ListPayload>(`/vulnerabilities?${params.toString()}`);
  const counts = vulns.data?.meta.counts ?? {};

  const update = async (id: string, patch: Record<string, unknown>) => {
    try {
      await api.patch(`/vulnerabilities/${id}`, patch);
      toast.push('success', 'Vulnerability updated');
      setSelected(null); vulns.refresh();
    } catch (err) { toast.push('error', 'Update failed', err instanceof ApiError ? err.message : undefined); }
  };

  return (
    <>
      <PageHeader title="Vulnerability management" subtitle="A register you maintain. Records come from analyst entry or a scanner import; SecureFlow does not invent findings."
        actions={permissions.canWrite ? <Button variant="primary" icon={<Plus size={14} aria-hidden="true" />} onClick={() => setCreateOpen(true)}>Record vulnerability</Button> : undefined} />

      <div className="grid grid-4" style={{ marginBottom: 14 }}>
        <div className="card kpi"><div className="kpi-label">Open</div><div className="kpi-value">{counts.open ?? 0}</div><div className="kpi-foot">Unmitigated findings</div></div>
        <div className="card kpi"><div className="kpi-label">In progress</div><div className="kpi-value">{counts.in_progress ?? 0}</div><div className="kpi-foot">Remediation underway</div></div>
        <div className="card kpi"><div className="kpi-label">Remediated</div><div className="kpi-value">{counts.remediated ?? 0}</div><div className="kpi-foot">Verified and closed</div></div>
        <div className="card kpi"><div className="kpi-label">Accepted</div><div className="kpi-value">{(counts.accepted ?? 0) + (counts.false_positive ?? 0)}</div><div className="kpi-foot">Risk accepted or invalid</div></div>
      </div>

      <Card bodyClass="">
        <div className="card-head" style={{ flexWrap: 'wrap', gap: 10 }}>
          <SearchInput value={query} onChange={(v) => { setQuery(v); setPage(1); }} placeholder="Search CVE, title or description" label="Search vulnerabilities" />
          <select className="select" style={{ width: 140 }} value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }} aria-label="Filter by severity">
            <option value="">Any severity</option>
            {['critical', 'high', 'medium', 'low'].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <select className="select" style={{ width: 160 }} value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }} aria-label="Filter by status">
            <option value="">Any status</option>
            {STATUSES.map((s) => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
          </select>
          <span className="tiny faint" style={{ marginLeft: 'auto' }}>{vulns.data?.meta.total ?? 0} records</span>
        </div>
        {vulns.loading && !vulns.data ? <TableSkeleton rows={7} cols={6} /> : vulns.error ? <ErrorState message={vulns.error} onRetry={vulns.refresh} /> : (
          <>
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>CVE</th><th>Vulnerability</th><th>Asset</th><th>Severity</th><th>CVSS</th><th>Status</th><th className="right">Due</th></tr></thead>
                <tbody>
                  {vulns.data?.data.map((vuln) => (
                    <tr key={vuln.id} className="row-link" onClick={() => setSelected(vuln)} tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter') setSelected(vuln); }}>
                      <td className="mono tiny">{vuln.cveId ?? '—'}</td>
                      <td><p className="truncate-cell" style={{ maxWidth: 360, fontWeight: 550 }}>{vuln.title}</p><OriginBadge origin={vuln.dataOrigin} /></td>
                      <td className="mono tiny muted">{vuln.assetHostname ?? 'Unassigned'}</td>
                      <td><SeverityBadge severity={vuln.severity} /></td>
                      <td className="num">{vuln.cvss.toFixed(1)}</td>
                      <td><StatusBadge status={vuln.status} /></td>
                      <td className="right tiny faint">{vuln.dueAt ? formatDate(vuln.dueAt, false) : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {vulns.data?.data.length === 0 && <EmptyState title="No vulnerabilities match" body="Record a finding or clear the filters." icon={<ShieldCheck size={18} aria-hidden="true" />} />}
            {vulns.data && vulns.data.data.length > 0 && <Pagination page={vulns.data.meta.page} totalPages={vulns.data.meta.totalPages} total={vulns.data.meta.total} onPage={setPage} />}
          </>
        )}
      </Card>

      <Drawer open={Boolean(selected)} onClose={() => setSelected(null)} title={selected?.title ?? 'Vulnerability'} subtitle={selected?.cveId ?? undefined}>
        {selected && (
          <>
            <div className="row wrap" style={{ gap: 8 }}><SeverityBadge severity={selected.severity} /><StatusBadge status={selected.status} /><Badge tone="neutral">CVSS {selected.cvss.toFixed(1)}</Badge></div>
            <p className="small muted">{selected.description}</p>
            <KeyValue items={[
              { label: 'Asset', value: selected.assetHostname ?? 'Unassigned' },
              { label: 'Discovered', value: formatDate(selected.discoveredAt) },
              { label: 'Due', value: selected.dueAt ? formatDate(selected.dueAt) : '—' },
            ]} />
            {selected.remediation && (
              <div>
                <p className="label">Remediation plan</p>
                <p className="small muted" style={{ marginTop: 4 }}>{selected.remediation}</p>
              </div>
            )}
            {permissions.canWrite && (
              <div className="stack" style={{ gap: 6 }}>
                <p className="label">Update status</p>
                <div className="row wrap" style={{ gap: 6 }}>
                  {STATUSES.filter((s) => s !== selected.status).map((next) => (
                    <Button key={next} size="sm" onClick={() => update(selected.id, { status: next })}>{next.replace('_', ' ')}</Button>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </Drawer>

      <CreateVulnModal open={createOpen} onClose={() => setCreateOpen(false)} onCreated={() => vulns.refresh()} />
    </>
  );
}

function CreateVulnModal({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: () => void }) {
  const toast = useToast();
  const assets = useApi<{ data: { id: string; hostname: string; name: string }[] }>('/assets?limit=100');
  const [form, setForm] = useState({ cveId: '', title: '', description: '', severity: 'high', cvss: 8.1, assetId: '', remediation: '' });
  const [error, setError] = useState<string | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setError(null); setErrors({});
    if (form.title.trim().length < 4) { setErrors({ title: 'Describe the vulnerability' }); return; }
    setBusy(true);
    try {
      await api.post('/vulnerabilities', {
        cveId: form.cveId.trim() || null, title: form.title.trim(), description: form.description.trim(),
        severity: form.severity, cvss: Number(form.cvss), assetId: form.assetId || null,
        remediation: form.remediation.trim() || null,
      });
      toast.push('success', 'Vulnerability recorded');
      onCreated(); onClose();
      setForm({ ...form, cveId: '', title: '', description: '', remediation: '' });
    } catch (err) {
      if (err instanceof ApiError) { setError(err.message); if (err.details) setErrors(Object.fromEntries(err.details.map((d) => [d.path, d.message]))); }
      else setError('Could not record the vulnerability');
    } finally { setBusy(false); }
  };

  return (
    <Modal open={open} onClose={onClose} title="Record a vulnerability" subtitle="Enter what a scanner reported or what you verified manually."
      footer={<><Button variant="ghost" onClick={onClose} type="button">Cancel</Button><Button variant="primary" onClick={submit} loading={busy} type="button">Record</Button></>}>
      {error && <div className="error-box" role="alert">{error}</div>}
      <div className="grid grid-2">
        <Field label="CVE identifier" htmlFor="v-cve"><input id="v-cve" className="input mono" value={form.cveId} onChange={(e) => setForm({ ...form, cveId: e.target.value })} placeholder="CVE-2024-3400" /></Field>
        <Field label="CVSS score" htmlFor="v-cvss"><input id="v-cvss" className="input" type="number" min={0} max={10} step={0.1} value={form.cvss} onChange={(e) => setForm({ ...form, cvss: Number(e.target.value) })} /></Field>
      </div>
      <Field label="Title" htmlFor="v-title" error={errors.title} required>
        <input id="v-title" className="input" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} placeholder="PAN-OS GlobalProtect command injection" />
      </Field>
      <div className="grid grid-2">
        <Field label="Severity" htmlFor="v-sev">
          <select id="v-sev" className="select" value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>{['critical', 'high', 'medium', 'low'].map((s) => <option key={s} value={s}>{s}</option>)}</select>
        </Field>
        <Field label="Affected asset" htmlFor="v-asset">
          <select id="v-asset" className="select" value={form.assetId} onChange={(e) => setForm({ ...form, assetId: e.target.value })}>
            <option value="">Unassigned</option>
            {(assets.data?.data ?? []).map((asset) => <option key={asset.id} value={asset.id}>{asset.hostname}</option>)}
          </select>
        </Field>
      </div>
      <Field label="Description" htmlFor="v-desc"><textarea id="v-desc" className="textarea" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
      <Field label="Remediation plan" htmlFor="v-rem"><textarea id="v-rem" className="textarea" value={form.remediation} onChange={(e) => setForm({ ...form, remediation: e.target.value })} placeholder="Patch level, compensating control, owner." /></Field>
    </Modal>
  );
}
