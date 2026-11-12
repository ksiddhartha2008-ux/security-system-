import { useState } from 'react';
import { Globe2, Plus, Search } from 'lucide-react';
import { PageHeader } from '../components/layout';
import { MetricCard } from '../components/design';
import {
  Badge, Button, Card, Drawer, EmptyState, ErrorState, Field, Modal, Pagination, RiskBadge,
  SearchInput, StatusBadge, TableSkeleton, useToast, CopyButton, InlineNotice,
} from '../components/ui';
import { useApi, useDebounced } from '../lib/hooks';
import { api, ApiError } from '../lib/api';
import { formatDate, timeAgo, titleCase } from '../lib/format';
import { useAuth } from '../lib/auth';

type Ioc = {
  id: string; type: string; value: string; threatType: string; confidence: number; source: string;
  description: string | null; status: string; lastSeenAt: string | null; createdAt: string;
};
type LookupResult = {
  query: string; type: string; verdict: string; score: number;
  localMatch: { id: string; threatType: string; confidence: number; source: string; description: string | null; status: string; lastSeenAt: string | null } | null;
  external: { provider: string; malicious?: number; suspicious?: number; harmless?: number; note?: string; error?: string; abuseConfidenceScore?: number; totalReports?: number; countryCode?: string }[];
  providersConfigured: boolean; note: string | null; lookedUpAt: string;
};
type IntelSummary = { total: number; active: number; highConfidence: number; sources: number };

const TYPES = ['ip', 'domain', 'url', 'sha256', 'md5', 'email'];

export default function IntelPage() {
  const { permissions } = useAuth();
  const toast = useToast();
  const [page, setPage] = useState(1);
  const [query, setQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [addOpen, setAddOpen] = useState(false);
  const [selected, setSelected] = useState<Ioc | null>(null);

  const [lookupQuery, setLookupQuery] = useState('');
  const [lookupType, setLookupType] = useState('auto');
  const [looking, setLooking] = useState(false);
  const [result, setResult] = useState<LookupResult | null>(null);
  const [lookupError, setLookupError] = useState<string | null>(null);

  const params = new URLSearchParams({ page: String(page), limit: '20' });
  if (typeFilter) params.set('type', typeFilter);
  if (query.trim()) params.set('q', query.trim());

  const iocs = useApi<{ data: Ioc[]; meta: { page: number; limit: number; total: number; totalPages: number } }>(`/threat-intel?${params.toString()}`);
  const intelSummary = useApi<IntelSummary>('/threat-intel/summary');
  const recent = useApi<{ id: string; type: string; value: string; verdict: string; score: number; source: string; createdAt: string }[]>('/threat-intel/lookups/recent');
  const debounced = useDebounced(query, 300);

  const runLookup = async () => {
    setLookupError(null);
    if (lookupQuery.trim().length < 3) { setLookupError('Enter an IP address, domain, URL, hash or email'); return; }
    setLooking(true);
    setResult(null);
    try {
      const data = await api.post<LookupResult>('/threat-intel/lookup', { query: lookupQuery.trim(), type: lookupType });
      setResult(data);
      recent.refresh();
    } catch (err) {
      setLookupError(err instanceof ApiError ? err.message : 'Lookup failed');
    } finally { setLooking(false); }
  };

  const updateStatus = async (ioc: Ioc, status: string) => {
    try {
      await api.patch(`/threat-intel/${ioc.id}`, { status });
      toast.push('success', 'Indicator updated');
      setSelected(null);
      iocs.refresh();
    } catch (err) { toast.push('error', 'Update failed', err instanceof ApiError ? err.message : undefined); }
  };

  return (
    <>
      <PageHeader title="Threat intelligence" subtitle="Indicators you track, with local matching and optional external enrichment. No provider is called unless its key is configured."
        actions={permissions.canWrite ? <Button variant="primary" icon={<Plus size={14} aria-hidden="true" />} onClick={() => setAddOpen(true)}>Add indicator</Button> : undefined} />

      <div className="grid grid-4" style={{ marginBottom: 14 }}>
        <MetricCard label="Indicators" value={intelSummary.data?.total ?? 0} foot="Tracked in this workspace" icon={<Globe2 size={12} aria-hidden="true" />} />
        <MetricCard label="Active" value={intelSummary.data?.active ?? 0} foot="Status active for matching" />
        <MetricCard label="High confidence" value={intelSummary.data?.highConfidence ?? 0} foot="Confidence 80 or higher" />
        <MetricCard label="Sources" value={intelSummary.data?.sources ?? 0} foot="Distinct feeds and manual sources" />
      </div>

      <div className="grid" style={{ gridTemplateColumns: '1.6fr 1fr', marginBottom: 14 }}>
        <Card title="Indicator lookup" subtitle="IP, domain, URL, file hash or email address">
          <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
            <div style={{ flex: 1, minWidth: 220 }}>
              <SearchInput value={lookupQuery} onChange={setLookupQuery} placeholder="203.0.113.44 or https://example.com/login" label="Indicator to look up" />
            </div>
            <select className="select" style={{ width: 130 }} value={lookupType} onChange={(e) => setLookupType(e.target.value)} aria-label="Indicator type">
              <option value="auto">Auto detect</option>
              {TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
            <Button variant="primary" onClick={runLookup} loading={looking} icon={<Search size={14} aria-hidden="true" />}>Look up</Button>
          </div>
          {lookupError && <div className="error-box" style={{ marginTop: 12 }} role="alert">{lookupError}</div>}
          {result && (
            <div style={{ marginTop: 14 }} className="stack">
              <div className="row" style={{ gap: 10, flexWrap: 'wrap' }}>
                <Badge tone={result.verdict === 'malicious' ? 'critical' : result.verdict === 'suspicious' ? 'medium' : result.verdict === 'known' ? 'low' : 'neutral'} dot>{result.verdict}</Badge>
                <span className="mono small">{result.query}</span>
                <RiskBadge score={result.score} />
                <CopyButton value={result.query} />
              </div>
              {result.localMatch ? (
                <div className="notice">
                  <p><strong>Workspace match.</strong> {titleCase(result.localMatch.threatType)} · confidence {result.localMatch.confidence} · source {result.localMatch.source}</p>
                  {result.localMatch.description && <p className="small" style={{ marginTop: 4 }}>{result.localMatch.description}</p>}
                </div>
              ) : <p className="small faint">No matching indicator in this workspace.</p>}
              {result.external.length > 0 && (
                <div className="stack" style={{ gap: 6 }}>
                  {result.external.map((provider, i) => (
                    <div key={`${provider.provider}-${i}`} className="row small" style={{ gap: 8 }}>
                      <Badge tone="neutral">{provider.provider}</Badge>
                      {provider.error ? <span style={{ color: '#ffb3b3' }}>{provider.error}</span> : provider.note ? <span className="muted">{provider.note}</span> : (
                        <span className="muted">
                          {provider.malicious !== undefined ? `${provider.malicious} malicious · ${provider.suspicious} suspicious · ${provider.harmless} harmless` : ''}
                          {provider.abuseConfidenceScore !== undefined ? `abuse confidence ${provider.abuseConfidenceScore}% · ${provider.totalReports} reports` : ''}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              )}
              {result.note && <InlineNotice tone="warn"><span className="small">{result.note}</span></InlineNotice>}
            </div>
          )}
        </Card>

        <Card title="Recent lookups" subtitle="Stored in this workspace">
          {recent.loading ? <TableSkeleton rows={4} cols={2} /> : (recent.data ?? []).length === 0 ? <p className="small faint">No lookups yet.</p> : (
            <div className="stack" style={{ gap: 8 }}>
              {recent.data?.slice(0, 7).map((row) => (
                <div key={row.id} className="row" style={{ gap: 8 }}>
                  <Badge tone={row.verdict === 'malicious' ? 'critical' : row.verdict === 'suspicious' ? 'medium' : 'neutral'}>{row.verdict}</Badge>
                  <span className="mono tiny truncate-cell" style={{ flex: 1 }} title={row.value}>{row.value}</span>
                  <span className="tiny faint">{timeAgo(row.createdAt)}</span>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      <Card bodyClass="">
        <div className="card-head">
          <SearchInput value={query} onChange={(v) => { setQuery(v); setPage(1); }} placeholder="Search indicators" label="Search indicators" />
          <select className="select" style={{ width: 140, marginLeft: 8 }} value={typeFilter} onChange={(e) => { setTypeFilter(e.target.value); setPage(1); }} aria-label="Filter by type">
            <option value="">All types</option>
            {TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <span className="tiny faint" style={{ marginLeft: 'auto' }}>{iocs.data?.meta.total ?? 0} indicators</span>
        </div>
        {iocs.loading && !iocs.data ? <TableSkeleton rows={7} cols={5} /> : iocs.error ? <ErrorState message={iocs.error} onRetry={iocs.refresh} /> : (
          <>
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>Type</th><th>Indicator</th><th>Threat</th><th>Confidence</th><th>Source</th><th>Status</th><th className="right">Last seen</th></tr></thead>
                <tbody>
                  {iocs.data?.data.map((ioc) => (
                    <tr key={ioc.id} className="row-link" onClick={() => setSelected(ioc)} tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter') setSelected(ioc); }}>
                      <td><Badge tone="neutral">{ioc.type}</Badge></td>
                      <td className="mono tiny truncate-cell" style={{ maxWidth: 330 }}>{ioc.value}</td>
                      <td className="small muted" style={{ textTransform: 'capitalize' }}>{ioc.threatType}</td>
                      <td className="num">{ioc.confidence}</td>
                      <td className="small muted">{ioc.source}</td>
                      <td><StatusBadge status={ioc.status} /></td>
                      <td className="right tiny faint">{timeAgo(ioc.lastSeenAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {iocs.data?.data.length === 0 && <EmptyState title="No indicators match" body="Add an indicator or clear the filter." icon={<Globe2 size={18} aria-hidden="true" />} />}
            {iocs.data && iocs.data.data.length > 0 && <Pagination page={iocs.data.meta.page} totalPages={iocs.data.meta.totalPages} total={iocs.data.meta.total} onPage={setPage} />}
          </>
        )}
      </Card>

      <Drawer open={Boolean(selected)} onClose={() => setSelected(null)} title={selected?.value ?? 'Indicator'} subtitle={selected ? `${selected.type} · ${selected.source}` : undefined}>
        {selected && (
          <>
            <div className="row wrap" style={{ gap: 8 }}><Badge tone="neutral">{selected.type}</Badge><StatusBadge status={selected.status} /><span className="tiny faint">confidence {selected.confidence}/100</span></div>
            <CopyButton value={selected.value} label="Copy indicator" />
            <dl className="kv">
              <dt>Threat type</dt><dd style={{ textTransform: 'capitalize' }}>{selected.threatType}</dd>
              <dt>Source</dt><dd>{selected.source}</dd>
              <dt>Last seen</dt><dd>{formatDate(selected.lastSeenAt)}</dd>
              <dt>Added</dt><dd>{formatDate(selected.createdAt)}</dd>
            </dl>
            {selected.description && <p className="small muted">{selected.description}</p>}
            {permissions.canWrite && (
              <div className="row wrap" style={{ gap: 8 }}>
                {['active', 'monitoring', 'retired'].filter((s) => s !== selected.status).map((status) => (
                  <Button key={status} size="sm" onClick={() => updateStatus(selected, status)}>Mark {status}</Button>
                ))}
              </div>
            )}
          </>
        )}
      </Drawer>

      <AddIocModal open={addOpen} onClose={() => setAddOpen(false)} onCreated={() => iocs.refresh()} />
    </>
  );
}

function AddIocModal({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: () => void }) {
  const toast = useToast();
  const [form, setForm] = useState({ type: 'ip', value: '', threatType: 'unknown', confidence: 60, description: '' });
  const [error, setError] = useState<string | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setError(null); setErrors({});
    if (!form.value.trim()) { setErrors({ value: 'Enter the indicator value' }); return; }
    setBusy(true);
    try {
      await api.post('/threat-intel', {
        type: form.type, value: form.value.trim(), threatType: form.threatType || 'unknown',
        confidence: Number(form.confidence), description: form.description.trim() || undefined,
      });
      toast.push('success', 'Indicator added');
      onCreated(); onClose();
      setForm({ ...form, value: '', description: '' });
    } catch (err) {
      if (err instanceof ApiError) { setError(err.message); if (err.details) setErrors(Object.fromEntries(err.details.map((d) => [d.path, d.message]))); }
      else setError('Could not add the indicator');
    } finally { setBusy(false); }
  };

  return (
    <Modal open={open} onClose={onClose} title="Add an indicator" subtitle="Indicators are scoped to your workspace and can be matched during lookups."
      footer={<><Button variant="ghost" onClick={onClose} type="button">Cancel</Button><Button variant="primary" onClick={submit} loading={busy} type="button">Add indicator</Button></>}>
      {error && <div className="error-box" role="alert">{error}</div>}
      <div className="grid grid-2">
        <Field label="Type" htmlFor="ioc-type">
          <select id="ioc-type" className="select" value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })}>{TYPES.map((t) => <option key={t} value={t}>{t}</option>)}</select>
        </Field>
        <Field label="Threat type" htmlFor="ioc-threat">
          <input id="ioc-threat" className="input" value={form.threatType} onChange={(e) => setForm({ ...form, threatType: e.target.value })} placeholder="phishing" />
        </Field>
      </div>
      <Field label="Value" htmlFor="ioc-value" error={errors.value} required>
        <input id="ioc-value" className="input mono" value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} placeholder={form.type === 'sha256' ? '64 hexadecimal characters' : '203.0.113.44'} />
      </Field>
      <Field label={`Confidence: ${form.confidence}`} htmlFor="ioc-conf">
        <input id="ioc-conf" type="range" min={0} max={100} value={form.confidence} onChange={(e) => setForm({ ...form, confidence: Number(e.target.value) })} style={{ width: '100%', accentColor: '#3ddc97' }} />
      </Field>
      <Field label="Context" htmlFor="ioc-desc">
        <textarea id="ioc-desc" className="textarea" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder="Where it was seen and why it matters." />
      </Field>
    </Modal>
  );
}
