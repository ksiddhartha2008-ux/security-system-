import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Radar, SlidersHorizontal } from 'lucide-react';
import { PageHeader } from '../components/layout';
import { MetricCard } from '../components/design';
import {
  Badge, Button, Card, Drawer, EmptyState, ErrorState, KeyValue, Pagination, RiskBadge,
  SearchInput, SeverityBadge, StatusBadge, TableSkeleton, Tabs, useToast, OriginBadge,
} from '../components/ui';
import { useApi, useDebounced } from '../lib/hooks';
import { api, ApiError } from '../lib/api';
import { formatDate, timeAgo } from '../lib/format';
import { useAuth } from '../lib/auth';

type Detection = { dataOrigin?: string;
  id: string; title: string; description: string; severity: string; riskScore: number; confidence: number;
  status: string; detectedAt: string; ruleName: string | null; ruleKey: string | null; assetId: string | null;
  assetHostname: string | null; explanation: {
    summary?: string; factors?: { label: string; weight: number; detail: string }[]; observed?: Record<string, unknown>;
    scoreModel?: string; deterministic?: boolean; ruleName?: string; windowMinutes?: number; feedback?: { status: string; note: string | null; by: string; at: string };
    signature?: string;
  };
};
type ListPayload = { data: Detection[]; meta: { page: number; limit: number; total: number; totalPages: number } };
type Summary = {
  status: Record<string, number>; severity: Record<string, number>; last24h: number;
  byRule: { key: string; name: string; c: number; avg_risk: number }[];
  scoreModel: { description: string };
};
type Rule = { id: string; key: string; name: string; category: string; severity: string; description: string; threshold: number; windowMinutes: number; enabled: boolean; supported: boolean };

export default function DetectionsPage() {
  const { permissions } = useAuth();
  const toast = useToast();
  const [tab, setTab] = useState<'queue' | 'rules'>('queue');
  const [status, setStatus] = useState<'open' | 'all' | string>('open');
  const [page, setPage] = useState(1);
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('');
  const [selected, setSelected] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const debounced = useDebounced(query, 300);

  const params = new URLSearchParams({ page: String(page), limit: '20' });
  if (status !== 'all') params.set('status', status);
  if (severity) params.set('severity', severity);
  if (debounced.trim()) params.set('q', debounced.trim());

  const detections = useApi<ListPayload>(`/detections?${params.toString()}`);
  const summary = useApi<Summary>('/detections/summary');
  const rules = useApi<Rule[]>('/detections/rules');
  const detail = useApi<Detection & { event: { id: string; title: string; src_ip: string | null } | null; relatedEvents: { id: string; title: string; severity: string; occurred_at: string }[] }>(
    selected ? `/detections/${selected}` : null,
  );

  const runRules = async () => {
    setBusy(true);
    try {
      const result = await api.post<{ produced: number }>('/detections/run');
      toast.push('success', 'Rules evaluated', result.produced ? `${result.produced} new detection(s) created.` : 'No new matches in the current window.');
      detections.refresh(); summary.refresh();
    } catch (err) { toast.push('error', 'Rule run failed', err instanceof ApiError ? err.message : undefined); }
    finally { setBusy(false); }
  };

  const feedback = async (id: string, next: 'confirmed' | 'false_positive' | 'closed') => {
    try {
      await api.post(`/detections/${id}/feedback`, { status: next });
      toast.push('success', `Detection marked ${next.replace('_', ' ')}`);
      setSelected(null); detections.refresh(); summary.refresh();
    } catch (err) { toast.push('error', 'Update failed', err instanceof ApiError ? err.message : undefined); }
  };

  const promote = async (id: string) => {
    try {
      const result = await api.post<{ ref: string }>(`/detections/${id}/promote`);
      toast.push('success', `Incident ${result.ref} created`);
      setSelected(null); detections.refresh(); summary.refresh();
    } catch (err) { toast.push('error', 'Could not create the incident', err instanceof ApiError ? err.message : undefined); }
  };

  const toggleRule = async (rule: Rule) => {
    try {
      await api.patch(`/detections/rules/${rule.id}`, { enabled: !rule.enabled });
      toast.push('success', `Rule ${rule.enabled ? 'disabled' : 'enabled'}`);
      rules.refresh();
    } catch (err) { toast.push('error', 'Could not change the rule', err instanceof ApiError ? err.message : undefined); }
  };

  return (
    <>
      <PageHeader title="Detections" subtitle="Deterministic rules with stored scoring factors. AI does not decide here; every score can be traced."
        actions={<>
          <Button icon={<SlidersHorizontal size={14} aria-hidden="true" />} onClick={() => setTab(tab === 'rules' ? 'queue' : 'rules')}>{tab === 'rules' ? 'Back to queue' : 'Rules'}</Button>
          {permissions.canWrite && <Button variant="primary" icon={<Radar size={14} aria-hidden="true" />} onClick={runRules} loading={busy}>Evaluate rules</Button>}
        </>} />

      <div className="grid grid-4" style={{ marginBottom: 14 }}>
        <MetricCard label="Open" value={summary.data?.status.open ?? 0} foot="Awaiting a decision" />
        <MetricCard label="Detected last 24h" value={summary.data?.last24h ?? 0} foot="Across all rules" />
        <MetricCard label="Confirmed" value={summary.data?.status.confirmed ?? 0} foot="Validated by an analyst" />
        <MetricCard label="False positives" value={summary.data?.status.false_positive ?? 0} foot="Kept for tuning history" />
      </div>

      {tab === 'queue' ? (
        <Card bodyClass="">
          <div style={{ padding: '0 16px' }}>
            <Tabs active={status} onChange={(key) => { setStatus(key); setPage(1); }} tabs={[
              { key: 'open', label: 'Open', count: summary.data?.status.open ?? 0 },
              { key: 'confirmed', label: 'Confirmed', count: summary.data?.status.confirmed ?? 0 },
              { key: 'false_positive', label: 'False positive', count: summary.data?.status.false_positive ?? 0 },
              { key: 'all', label: 'All' },
            ]} />
          </div>
          <div className="card-head" style={{ flexWrap: 'wrap', gap: 10 }}>
            <SearchInput value={query} onChange={(v) => { setQuery(v); setPage(1); }} placeholder="Search detections" label="Search detections" />
            <select className="select" style={{ width: 150 }} value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }} aria-label="Filter by severity">
              <option value="">Any severity</option>
              {['critical', 'high', 'medium', 'low'].map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <span className="tiny faint" style={{ marginLeft: 'auto' }}>{detections.data?.meta.total ?? 0} detections</span>
          </div>
          {detections.loading && !detections.data ? <TableSkeleton rows={7} cols={5} /> : detections.error ? <ErrorState message={detections.error} onRetry={detections.refresh} /> : (
            <>
              <div className="table-wrap">
                <table className="data">
                  <thead><tr><th>Severity</th><th>Detection</th><th>Rule</th><th>Asset</th><th>Risk</th><th>Confidence</th><th>Status</th><th className="right">Detected</th></tr></thead>
                  <tbody>
                    {detections.data?.data.map((detection) => (
                      <tr key={detection.id} className="row-link" onClick={() => setSelected(detection.id)} tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter') setSelected(detection.id); }}>
                        <td><SeverityBadge severity={detection.severity} /></td>
                        <td>
                          <p className="truncate-cell" style={{ maxWidth: 340, fontWeight: 550 }}>{detection.title}</p>
                          <p className="tiny faint truncate-cell" style={{ maxWidth: 340 }}>{detection.description}</p>
                          <OriginBadge origin={detection.dataOrigin} />
                        </td>
                        <td className="small muted">{detection.ruleName ?? 'historical'}</td>
                        <td className="mono tiny muted">{detection.assetHostname ?? '—'}</td>
                        <td><RiskBadge score={detection.riskScore} /></td>
                        <td className="num">{detection.confidence}</td>
                        <td><StatusBadge status={detection.status} /></td>
                        <td className="right tiny faint">{timeAgo(detection.detectedAt)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {detections.data?.data.length === 0 && <EmptyState title="Nothing in this queue" body="Rules run automatically when events arrive. Use Evaluate rules to check the current window again." icon={<Radar size={18} aria-hidden="true" />} />}
              {detections.data && detections.data.data.length > 0 && <Pagination page={detections.data.meta.page} totalPages={detections.data.meta.totalPages} total={detections.data.meta.total} onPage={setPage} />}
            </>
          )}
        </Card>
      ) : (
        <Card title="Detection rules" subtitle="Thresholds are enforced server side. The rule evaluation window is stored per detection.">
          {rules.loading ? <TableSkeleton rows={6} cols={4} /> : rules.error ? <ErrorState message={rules.error} onRetry={rules.refresh} /> : (
            <div className="stack" style={{ gap: 10 }}>
              {(rules.data ?? []).map((rule) => (
                <div key={rule.id} className="row" style={{ gap: 12, padding: '10px 12px', border: '1px solid var(--color-line)', borderRadius: 9, alignItems: 'flex-start' }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
                      <span style={{ fontWeight: 600, fontSize: 13 }}>{rule.name}</span>
                      <SeverityBadge severity={rule.severity} />
                      <Badge tone="neutral">{rule.category}</Badge>
                      {!rule.enabled && <Badge tone="neutral">disabled</Badge>}
                    </div>
                    <p className="small muted" style={{ marginTop: 4 }}>{rule.description}</p>
                    <p className="tiny faint" style={{ marginTop: 4 }}>Threshold {rule.threshold} · window {rule.windowMinutes} min · key {rule.key}</p>
                  </div>
                  {permissions.canAdmin ? (
                    <button className={`btn btn-sm ${rule.enabled ? '' : 'btn-primary'}`} onClick={() => toggleRule(rule)} type="button">{rule.enabled ? 'Disable' : 'Enable'}</button>
                  ) : <Badge tone={rule.enabled ? 'mint' : 'neutral'}>{rule.enabled ? 'enabled' : 'disabled'}</Badge>}
                </div>
              ))}
              <p className="tiny faint" style={{ marginTop: 4 }}>{summary.data?.scoreModel.description}</p>
            </div>
          )}
        </Card>
      )}

      <Drawer open={Boolean(selected)} onClose={() => setSelected(null)} title={detail.data?.title ?? 'Detection'} subtitle={detail.data ? `${detail.data.ruleName ?? 'historical'} · risk ${detail.data.riskScore}/100` : undefined}
        footer={detail.data && permissions.canWrite ? (
          <div className="row wrap" style={{ gap: 8, marginLeft: 'auto' }}>
            <Button size="sm" onClick={() => promote(detail.data!.id)}>Promote to incident</Button>
            <Button size="sm" variant="ghost" onClick={() => feedback(detail.data!.id, 'false_positive')}>False positive</Button>
            <Button size="sm" variant="primary" onClick={() => feedback(detail.data!.id, 'confirmed')}>Confirm</Button>
          </div>
        ) : undefined}>
        {detail.loading && <TableSkeleton rows={6} cols={2} />}
        {detail.error && <ErrorState message={detail.error} onRetry={detail.refresh} />}
        {detail.data && (
          <>
            <div className="row wrap" style={{ gap: 8 }}>
              <SeverityBadge severity={detail.data.severity} />
              <StatusBadge status={detail.data.status} />
              <RiskBadge score={detail.data.riskScore} />
              <span className="tiny faint">confidence {detail.data.confidence}%</span>
            </div>
            <p className="small" style={{ color: 'var(--color-ink-soft)' }}>{detail.data.description}</p>
            <KeyValue items={[
              { label: 'Rule', value: detail.data.ruleName ?? 'historical replay' },
              { label: 'Detected', value: formatDate(detail.data.detectedAt) },
              { label: 'Asset', value: detail.data.assetHostname ?? '—' },
              { label: 'Signature', value: <span className="mono tiny">{detail.data.explanation.signature ?? '—'}</span> },
            ]} />

            <div>
              <p className="label">Why this score</p>
              <p className="small muted" style={{ marginTop: 4 }}>{detail.data.explanation.summary ?? 'No explanation stored.'}</p>
              <div className="stack" style={{ gap: 8, marginTop: 10 }}>
                {(detail.data.explanation.factors ?? []).map((factor) => (
                  <div key={factor.label}>
                    <div className="row-between tiny"><span>{factor.label}</span><span className="faint">{factor.weight}</span></div>
                    <div className="bar-track" style={{ marginTop: 3 }}><div className="bar-fill" style={{ width: `${Math.min(100, factor.weight * 2)}%`, background: 'var(--color-info-text)' }} /></div>
                    <p className="tiny faint" style={{ marginTop: 2 }}>{factor.detail}</p>
                  </div>
                ))}
              </div>
              <p className="tiny faint" style={{ marginTop: 8 }}>{detail.data.explanation.scoreModel}</p>
            </div>

            <div>
              <p className="label">Observed values</p>
              <pre className="code-block">{JSON.stringify(detail.data.explanation.observed ?? {}, null, 2)}</pre>
            </div>

            {detail.data.event && (
              <div>
                <p className="label">Source event</p>
                <Link to="/monitoring" className="small row" style={{ gap: 6, marginTop: 4 }}>
                  <Badge tone="neutral">{detail.data.event.src_ip ?? 'no ip'}</Badge>
                  <span className="truncate-cell">{detail.data.event.title}</span>
                </Link>
              </div>
            )}

            <div>
              <p className="label">Related telemetry</p>
              {detail.data.relatedEvents.length === 0 ? <p className="small faint">No related events.</p> : detail.data.relatedEvents.map((event) => (
                <div key={event.id} className="row" style={{ gap: 8, padding: '4px 0' }}>
                  <SeverityBadge severity={event.severity} />
                  <span className="small truncate-cell" style={{ flex: 1 }}>{event.title}</span>
                  <span className="tiny faint">{timeAgo(event.occurred_at)}</span>
                </div>
              ))}
            </div>

            {detail.data.explanation.feedback && (
              <div className="notice">
                <p className="small"><strong>Analyst feedback:</strong> {detail.data.explanation.feedback.status.replace('_', ' ')}</p>
                {detail.data.explanation.feedback.note && <p className="tiny">{detail.data.explanation.feedback.note}</p>}
              </div>
            )}
          </>
        )}
      </Drawer>
    </>
  );
}
