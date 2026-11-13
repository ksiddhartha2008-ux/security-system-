import { useState } from 'react';
import { Network as NetworkIcon, Plus } from 'lucide-react';
import { PageHeader } from '../components/layout';
import {
  Badge, Button, Card, ErrorState, Field, Modal, Pagination, SearchInput, StatusBadge, TableSkeleton,
  useToast, EmptyState,
} from '../components/ui';
import { Donut, RankBars } from '../components/charts';
import { useApi, useDebounced } from '../lib/hooks';
import { api, ApiError } from '../lib/api';
import { formatBytes, formatNumber, timeAgo } from '../lib/format';
import { useAuth } from '../lib/auth';

type Flow = {
  id: string; srcIp: string; srcPort: number | null; destIp: string; destPort: number | null; protocol: string;
  bytesOut: number; bytesIn: number; direction: string; verdict: string; assetHostname: string | null; occurredAt: string;
};
type ListPayload = { data: Flow[]; meta: { page: number; limit: number; total: number; totalPages: number } };
type Summary = {
  totals: { flows: number; bytesOut: number; bytesIn: number; suspicious: number; blocked: number; last24h: number };
  protocols: { protocol: string; c: number; bytes: number }[];
  topSources: { src_ip: string; flows: number; bytes: number }[];
  topDestinations: { dest_ip: string; flows: number; bytes: number }[];
  topPorts: { dest_port: number; c: number }[];
};

const PROTOCOL_COLORS: Record<string, string> = { TCP: 'var(--color-mint)', UDP: 'var(--color-info-text)', TLS: 'var(--color-mint-bright)', DNS: 'var(--color-amber)', HTTP: 'var(--color-orange)', ICMP: 'var(--color-muted)' };

export default function NetworkPage() {
  const { permissions } = useAuth();
  const toast = useToast();
  const [page, setPage] = useState(1);
  const [query, setQuery] = useState('');
  const [verdict, setVerdict] = useState('');
  const [createOpen, setCreateOpen] = useState(false);
  const debounced = useDebounced(query, 300);

  const params = new URLSearchParams({ page: String(page), limit: '30' });
  if (debounced.trim()) params.set('q', debounced.trim());
  if (verdict) params.set('verdict', verdict);

  const flows = useApi<ListPayload>(`/network?${params.toString()}`);
  const summary = useApi<Summary>('/network/summary');

  return (
    <>
      <PageHeader title="Network monitoring" subtitle="Flow records from sensors and gateways. Suspicious flows are highlighted; nothing is blocked by this application."
        actions={permissions.canWrite ? <Button variant="primary" icon={<Plus size={14} aria-hidden="true" />} onClick={() => setCreateOpen(true)}>Ingest flow</Button> : undefined} />

      <div className="grid grid-4" style={{ marginBottom: 14 }}>
        <div className="card kpi"><div className="kpi-label">Flows recorded</div><div className="kpi-value">{formatNumber(summary.data?.totals.flows)}</div><div className="kpi-foot">{formatNumber(summary.data?.totals.last24h)} in the last 24 hours</div></div>
        <div className="card kpi"><div className="kpi-label">Outbound volume</div><div className="kpi-value">{formatBytes(summary.data?.totals.bytesOut)}</div><div className="kpi-foot">{formatBytes(summary.data?.totals.bytesIn)} inbound</div></div>
        <div className="card kpi"><div className="kpi-label">Suspicious flows</div><div className="kpi-value">{formatNumber(summary.data?.totals.suspicious)}</div><div className="kpi-foot">Flagged by the sensor or an analyst</div></div>
        <div className="card kpi"><div className="kpi-label">Blocked</div><div className="kpi-value">{formatNumber(summary.data?.totals.blocked)}</div><div className="kpi-foot">Dropped at a gateway</div></div>
      </div>

      <div className="grid grid-3" style={{ marginBottom: 14 }}>
        <Card title="Protocols" subtitle="Share of recorded flows">
          <Donut size={150} centerValue={formatNumber(summary.data?.protocols.reduce((a, b) => a + b.c, 0))} centerLabel="FLOWS"
            segments={(summary.data?.protocols ?? []).map((p) => ({ label: p.protocol, value: p.c, color: PROTOCOL_COLORS[p.protocol] ?? 'var(--color-muted)' }))} />
        </Card>
        <Card title="Top sources by volume" subtitle="Bytes out">
          <RankBars items={(summary.data?.topSources ?? []).slice(0, 6).map((s) => ({ label: s.src_ip, value: s.bytes, hint: formatBytes(s.bytes) }))} color="var(--color-mint)" />
        </Card>
        <Card title="Destination ports" subtitle="Most requested services">
          <RankBars items={(summary.data?.topPorts ?? []).slice(0, 6).map((p) => ({ label: `port ${p.dest_port}`, value: p.c }))} color="var(--color-info-text)" />
        </Card>
      </div>

      <Card bodyClass="">
        <div className="card-head" style={{ flexWrap: 'wrap', gap: 10 }}>
          <SearchInput value={query} onChange={(v) => { setQuery(v); setPage(1); }} placeholder="Search source or destination IP" label="Search flows" />
          <select className="select" style={{ width: 150 }} value={verdict} onChange={(e) => { setVerdict(e.target.value); setPage(1); }} aria-label="Filter by verdict">
            <option value="">Any verdict</option>
            {['allowed', 'suspicious', 'blocked'].map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
          <span className="tiny faint" style={{ marginLeft: 'auto' }}>{flows.data?.meta.total ?? 0} flows</span>
        </div>
        {flows.loading && !flows.data ? <TableSkeleton rows={8} cols={6} /> : flows.error ? <ErrorState message={flows.error} onRetry={flows.refresh} /> : (
          <>
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Volume</th><th>Direction</th><th>Verdict</th><th>Asset</th><th className="right">When</th></tr></thead>
                <tbody>
                  {flows.data?.data.map((flow) => (
                    <tr key={flow.id}>
                      <td className="mono tiny">{flow.srcIp}{flow.srcPort ? `:${flow.srcPort}` : ''}</td>
                      <td className="mono tiny">{flow.destIp}{flow.destPort ? `:${flow.destPort}` : ''}</td>
                      <td><Badge tone="neutral">{flow.protocol}</Badge></td>
                      <td className="num tiny">{formatBytes(flow.bytesOut)} out</td>
                      <td className="small muted">{flow.direction}</td>
                      <td><StatusBadge status={flow.verdict} /></td>
                      <td className="mono tiny muted">{flow.assetHostname ?? '—'}</td>
                      <td className="right tiny faint">{timeAgo(flow.occurredAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {flows.data?.data.length === 0 && <EmptyState title="No flows match" body="Clear the filters or ingest a flow record." icon={<NetworkIcon size={18} aria-hidden="true" />} />}
            {flows.data && flows.data.data.length > 0 && <Pagination page={flows.data.meta.page} totalPages={flows.data.meta.totalPages} total={flows.data.meta.total} onPage={setPage} />}
          </>
        )}
      </Card>

      <IngestFlowModal open={createOpen} onClose={() => setCreateOpen(false)} onCreated={() => { flows.refresh(); summary.refresh(); }} />
    </>
  );
}

function IngestFlowModal({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: () => void }) {
  const toast = useToast();
  const [form, setForm] = useState({ srcIp: '', destIp: '', destPort: 443, protocol: 'TLS', bytesOut: 1024, verdict: 'allowed', direction: 'outbound' });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setError(null);
    if (!form.srcIp.trim() || !form.destIp.trim()) { setError('Source and destination addresses are required'); return; }
    setBusy(true);
    try {
      await api.post('/network', { ...form, srcPort: 51000 });
      toast.push('success', 'Flow ingested');
      onCreated(); onClose();
    } catch (err) { setError(err instanceof ApiError ? err.message : 'Could not ingest the flow'); }
    finally { setBusy(false); }
  };

  return (
    <Modal open={open} onClose={onClose} title="Ingest a flow record" subtitle="Use this to add a record from a sensor that is not yet integrated."
      footer={<><Button variant="ghost" onClick={onClose} type="button">Cancel</Button><Button variant="primary" onClick={submit} loading={busy} type="button">Ingest</Button></>}>
      {error && <div className="error-box" role="alert">{error}</div>}
      <div className="grid grid-2">
        <Field label="Source IP" htmlFor="n-src" required><input id="n-src" className="input mono" value={form.srcIp} onChange={(e) => setForm({ ...form, srcIp: e.target.value })} placeholder="10.20.1.11" /></Field>
        <Field label="Destination IP" htmlFor="n-dst" required><input id="n-dst" className="input mono" value={form.destIp} onChange={(e) => setForm({ ...form, destIp: e.target.value })} placeholder="198.51.100.5" /></Field>
        <Field label="Destination port" htmlFor="n-port"><input id="n-port" type="number" className="input" value={form.destPort} onChange={(e) => setForm({ ...form, destPort: Number(e.target.value) })} /></Field>
        <Field label="Protocol" htmlFor="n-proto"><select id="n-proto" className="select" value={form.protocol} onChange={(e) => setForm({ ...form, protocol: e.target.value })}>{['TCP', 'UDP', 'ICMP', 'TLS', 'DNS', 'HTTP'].map((p) => <option key={p} value={p}>{p}</option>)}</select></Field>
        <Field label="Bytes out" htmlFor="n-bytes"><input id="n-bytes" type="number" className="input" value={form.bytesOut} onChange={(e) => setForm({ ...form, bytesOut: Number(e.target.value) })} /></Field>
        <Field label="Verdict" htmlFor="n-verdict"><select id="n-verdict" className="select" value={form.verdict} onChange={(e) => setForm({ ...form, verdict: e.target.value })}>{['allowed', 'suspicious', 'blocked'].map((v) => <option key={v} value={v}>{v}</option>)}</select></Field>
      </div>
    </Modal>
  );
}
