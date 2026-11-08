import { useState } from 'react';
import { Plus, Server } from 'lucide-react';
import { PageHeader } from '../components/layout';
import {
  Badge, Button, Card, Drawer, EmptyState, ErrorState, Field, Modal, Pagination, RiskBadge,
  SearchInput, SeverityBadge, StatusBadge, TableSkeleton, useToast, KeyValue,
} from '../components/ui';
import { useApi, useDebounced } from '../lib/hooks';
import { api, ApiError } from '../lib/api';
import { formatDate, timeAgo } from '../lib/format';
import { useAuth } from '../lib/auth';

type Asset = {
  id: string; name: string; hostname: string; ipAddress: string | null; os: string | null; assetType: string;
  criticality: string; owner: string | null; riskScore: number; status: string; tags: string[];
  eventCount?: number; openDetections?: number; lastSeenAt: string | null;
};
type List = { data: Asset[]; meta: { page: number; limit: number; total: number; totalPages: number } };
type Detail = Asset & {
  events: { id: string; title: string; event_type: string; severity: string; occurred_at: string }[];
  detections: { id: string; title: string; severity: string; risk_score: number; status: string }[];
  vulnerabilities: { id: string; cve_id: string | null; title: string; severity: string; cvss: number; status: string }[];
  network: { id: string; src_ip: string; dest_ip: string; dest_port: number; bytes_out: number; verdict: string; occurred_at: string }[];
};

const CRITICALITIES = ['critical', 'high', 'medium', 'low'];
const TYPES = ['server', 'workstation', 'database', 'network', 'cloud', 'container host', 'ot', 'mobile'];

export default function AssetsPage() {
  const { permissions } = useAuth();
  const toast = useToast();
  const [page, setPage] = useState(1);
  const [query, setQuery] = useState('');
  const [criticality, setCriticality] = useState('');
  const [status, setStatus] = useState('');
  const [selected, setSelected] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const debounced = useDebounced(query, 300);

  const params = new URLSearchParams({ page: String(page), limit: '25' });
  if (debounced.trim()) params.set('q', debounced.trim());
  if (criticality) params.set('criticality', criticality);
  if (status) params.set('status', status);

  const assets = useApi<List>(`/assets?${params.toString()}`);
  const summary = useApi<{ byCriticality: { criticality: string; count: number; avgRisk: number }[]; byType: { assetType: string; count: number }[] }>('/assets/summary');
  const detail = useApi<Detail>(selected ? `/assets/${selected}` : null);

  const updateAsset = async (patch: Record<string, unknown>) => {
    if (!selected) return;
    try {
      await api.patch(`/assets/${selected}`, patch);
      toast.push('success', 'Asset updated');
      detail.refresh();
      assets.refresh();
    } catch (err) {
      toast.push('error', 'Update failed', err instanceof ApiError ? err.message : undefined);
    }
  };

  return (
    <>
      <PageHeader title="Asset inventory" subtitle="What you are defending. Criticality feeds detection scoring; risk rises when open detections reference an asset."
        actions={permissions.canWrite ? <Button variant="primary" icon={<Plus size={14} aria-hidden="true" />} onClick={() => setCreateOpen(true)}>Register asset</Button> : undefined} />

      <div className="grid grid-4" style={{ marginBottom: 14 }}>
        {CRITICALITIES.map((level) => {
          const row = summary.data?.byCriticality.find((c) => c.criticality === level);
          return (
            <button key={level} type="button" className="card kpi" style={{ textAlign: 'left', cursor: 'pointer', borderColor: criticality === level ? 'rgba(61,220,151,0.45)' : undefined }}
              onClick={() => { setCriticality(criticality === level ? '' : level); setPage(1); }}>
              <div className="kpi-label"><span style={{ textTransform: 'capitalize' }}>{level} assets</span></div>
              <div className="kpi-value">{row?.count ?? 0}</div>
              <div className="kpi-foot">Mean risk {row?.avgRisk ?? 0}/100</div>
            </button>
          );
        })}
      </div>

      <Card bodyClass="">
        <div className="card-head" style={{ flexWrap: 'wrap', gap: 10 }}>
          <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
            <SearchInput value={query} onChange={(v) => { setQuery(v); setPage(1); }} placeholder="Search name, host, IP or owner" label="Search assets" />
            <select className="select" style={{ width: 150 }} value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }} aria-label="Filter by status">
              <option value="">Any status</option>
              {['online', 'offline', 'quarantined', 'decommissioned'].map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            {(query || criticality || status) && <Button size="sm" variant="ghost" onClick={() => { setQuery(''); setCriticality(''); setStatus(''); setPage(1); }}>Clear</Button>}
          </div>
          <span className="tiny faint" style={{ marginLeft: 'auto' }}>{assets.data?.meta.total ?? 0} assets</span>
        </div>

        {assets.loading && !assets.data ? <TableSkeleton rows={8} cols={6} /> : assets.error ? <ErrorState message={assets.error} onRetry={assets.refresh} /> : (
          <>
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>Asset</th><th>Address</th><th>Type</th><th>Criticality</th><th>Risk</th><th>Status</th><th className="right">Last seen</th></tr></thead>
                <tbody>
                  {assets.data?.data.map((asset) => (
                    <tr key={asset.id} className="row-link" onClick={() => setSelected(asset.id)} tabIndex={0}
                      onKeyDown={(e) => { if (e.key === 'Enter') setSelected(asset.id); }}>
                      <td>
                        <p style={{ fontWeight: 550 }}>{asset.name}</p>
                        <p className="tiny faint mono">{asset.hostname}{asset.owner ? ` · ${asset.owner}` : ''}</p>
                      </td>
                      <td className="mono tiny muted">{asset.ipAddress ?? 'cloud'}</td>
                      <td className="small muted">{asset.assetType}</td>
                      <td><Badge tone={asset.criticality === 'critical' ? 'critical' : asset.criticality === 'high' ? 'high' : asset.criticality === 'medium' ? 'medium' : 'low'}>{asset.criticality}</Badge></td>
                      <td><RiskBadge score={asset.riskScore} /></td>
                      <td><StatusBadge status={asset.status} /></td>
                      <td className="right tiny faint">{timeAgo(asset.lastSeenAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {assets.data?.data.length === 0 && <EmptyState title="No assets match" body="Register an asset or clear the filters." icon={<Server size={18} aria-hidden="true" />} />}
            {assets.data && assets.data.data.length > 0 && <Pagination page={assets.data.meta.page} totalPages={assets.data.meta.totalPages} total={assets.data.meta.total} onPage={setPage} />}
          </>
        )}
      </Card>

      <Drawer open={Boolean(selected)} onClose={() => setSelected(null)} title={detail.data?.name ?? 'Asset'} subtitle={detail.data ? `${detail.data.hostname} · ${detail.data.assetType}` : undefined}>
        {detail.loading && <TableSkeleton rows={6} cols={2} />}
        {detail.error && <ErrorState message={detail.error} onRetry={detail.refresh} />}
        {detail.data && (
          <>
            <div className="row wrap" style={{ gap: 8 }}>
              <Badge tone={detail.data.criticality === 'critical' ? 'critical' : detail.data.criticality === 'high' ? 'high' : 'medium'}>{detail.data.criticality}</Badge>
              <StatusBadge status={detail.data.status} />
              <RiskBadge score={detail.data.riskScore} />
              {detail.data.tags.map((tag) => <span className="chip" key={tag}>{tag}</span>)}
            </div>
            <KeyValue items={[
              { label: 'Hostname', value: <span className="mono">{detail.data.hostname}</span> },
              { label: 'IP address', value: <span className="mono">{detail.data.ipAddress ?? '—'}</span> },
              { label: 'Operating system', value: detail.data.os ?? '—' },
              { label: 'Owner', value: detail.data.owner ?? '—' },
              { label: 'Last seen', value: formatDate(detail.data.lastSeenAt) },
            ]} />

            {permissions.canWrite && (
              <div className="grid grid-2">
                <Field label="Criticality" htmlFor="asset-criticality">
                  <select id="asset-criticality" className="select" value={detail.data.criticality} onChange={(e) => updateAsset({ criticality: e.target.value })}>
                    {CRITICALITIES.map((c) => <option key={c} value={c}>{c}</option>)}
                  </select>
                </Field>
                <Field label="Status" htmlFor="asset-status">
                  <select id="asset-status" className="select" value={detail.data.status} onChange={(e) => updateAsset({ status: e.target.value })}>
                    {['online', 'offline', 'quarantined', 'decommissioned'].map((s) => <option key={s} value={s}>{s}</option>)}
                  </select>
                </Field>
              </div>
            )}

            <div>
              <p className="label" style={{ marginBottom: 6 }}>Recent events ({detail.data.events.length})</p>
              {detail.data.events.length === 0 ? <p className="small faint">No telemetry attached yet.</p> : detail.data.events.map((event) => (
                <div key={event.id} className="row" style={{ padding: '5px 0', gap: 8 }}>
                  <SeverityBadge severity={event.severity} />
                  <span className="small truncate-cell" style={{ flex: 1 }}>{event.title}</span>
                  <span className="tiny faint">{timeAgo(event.occurred_at)}</span>
                </div>
              ))}
            </div>

            <div>
              <p className="label" style={{ marginBottom: 6 }}>Detections ({detail.data.detections.length})</p>
              {detail.data.detections.length === 0 ? <p className="small faint">No detection references this asset.</p> : detail.data.detections.map((d) => (
                <div key={d.id} className="row" style={{ padding: '5px 0', gap: 8 }}>
                  <SeverityBadge severity={d.severity} />
                  <span className="small truncate-cell" style={{ flex: 1 }}>{d.title}</span>
                  <RiskBadge score={d.risk_score} />
                </div>
              ))}
            </div>

            <div>
              <p className="label" style={{ marginBottom: 6 }}>Vulnerabilities ({detail.data.vulnerabilities.length})</p>
              {detail.data.vulnerabilities.length === 0 ? <p className="small faint">No vulnerability is mapped to this asset.</p> : detail.data.vulnerabilities.map((v) => (
                <div key={v.id} className="row" style={{ padding: '5px 0', gap: 8 }}>
                  <SeverityBadge severity={v.severity} />
                  <span className="small truncate-cell" style={{ flex: 1 }}>{v.cve_id ?? 'No CVE'} · {v.title}</span>
                  <span className="mono tiny muted">{v.cvss.toFixed(1)}</span>
                </div>
              ))}
            </div>

            <div>
              <p className="label" style={{ marginBottom: 6 }}>Network flows ({detail.data.network.length})</p>
              {detail.data.network.length === 0 ? <p className="small faint">No flow records for this asset.</p> : detail.data.network.map((n) => (
                <div key={n.id} className="row mono tiny" style={{ padding: '4px 0', gap: 8, color: '#94a6b8' }}>
                  <span style={{ flex: 1 }}>{n.src_ip} → {n.dest_ip}:{n.dest_port}</span>
                  <span>{Math.round(n.bytes_out / 1024)} KB</span>
                  <StatusBadge status={n.verdict} />
                </div>
              ))}
            </div>
          </>
        )}
      </Drawer>

      <CreateAssetModal open={createOpen} onClose={() => setCreateOpen(false)} onCreated={() => { assets.refresh(); summary.refresh(); }} />
    </>
  );
}

function CreateAssetModal({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: () => void }) {
  const toast = useToast();
  const [form, setForm] = useState({ name: '', hostname: '', ipAddress: '', os: '', assetType: 'server', criticality: 'medium', owner: '', tags: '' });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setError(null); setErrors({});
    if (form.name.trim().length < 2) { setErrors({ name: 'Enter an asset name' }); return; }
    if (!form.hostname.trim()) { setErrors({ hostname: 'Enter a hostname' }); return; }
    setBusy(true);
    try {
      await api.post('/assets', {
        name: form.name.trim(), hostname: form.hostname.trim(), ipAddress: form.ipAddress.trim() || null,
        os: form.os.trim() || null, assetType: form.assetType, criticality: form.criticality,
        owner: form.owner.trim() || null, tags: form.tags.split(',').map((t) => t.trim()).filter(Boolean),
      });
      toast.push('success', 'Asset registered');
      onCreated(); onClose();
      setForm({ name: '', hostname: '', ipAddress: '', os: '', assetType: 'server', criticality: 'medium', owner: '', tags: '' });
    } catch (err) {
      if (err instanceof ApiError) { setError(err.message); if (err.details) setErrors(Object.fromEntries(err.details.map((d) => [d.path, d.message]))); }
      else setError('Could not register the asset');
    } finally { setBusy(false); }
  };

  return (
    <Modal open={open} onClose={onClose} title="Register an asset" subtitle="Assets give telemetry and detections a place to point."
      footer={<><Button variant="ghost" onClick={onClose} type="button">Cancel</Button><Button variant="primary" onClick={submit} loading={busy} type="button">Register</Button></>}>
      {error && <div className="error-box" role="alert">{error}</div>}
      <div className="grid grid-2">
        <Field label="Name" htmlFor="a-name" error={errors.name} required><input id="a-name" className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Production web front end" /></Field>
        <Field label="Hostname" htmlFor="a-host" error={errors.hostname} required><input id="a-host" className="input mono" value={form.hostname} onChange={(e) => setForm({ ...form, hostname: e.target.value })} placeholder="web-prod-01" /></Field>
        <Field label="IP address" htmlFor="a-ip"><input id="a-ip" className="input mono" value={form.ipAddress} onChange={(e) => setForm({ ...form, ipAddress: e.target.value })} placeholder="10.20.1.11" /></Field>
        <Field label="Operating system" htmlFor="a-os"><input id="a-os" className="input" value={form.os} onChange={(e) => setForm({ ...form, os: e.target.value })} placeholder="Ubuntu 24.04 LTS" /></Field>
        <Field label="Type" htmlFor="a-type"><select id="a-type" className="select" value={form.assetType} onChange={(e) => setForm({ ...form, assetType: e.target.value })}>{TYPES.map((t) => <option key={t} value={t}>{t}</option>)}</select></Field>
        <Field label="Criticality" htmlFor="a-crit"><select id="a-crit" className="select" value={form.criticality} onChange={(e) => setForm({ ...form, criticality: e.target.value })}>{CRITICALITIES.map((c) => <option key={c} value={c}>{c}</option>)}</select></Field>
        <Field label="Owner" htmlFor="a-owner"><input id="a-owner" className="input" value={form.owner} onChange={(e) => setForm({ ...form, owner: e.target.value })} placeholder="Platform team" /></Field>
        <Field label="Tags" htmlFor="a-tags" hint="Comma separated"><input id="a-tags" className="input" value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} placeholder="pci, internet-facing" /></Field>
      </div>
    </Modal>
  );
}
