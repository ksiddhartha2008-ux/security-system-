import { Link } from 'react-router-dom';
import {
  Activity, AlertTriangle, ArrowUpRight, CheckCircle2, FlaskConical, Radar, Server, Siren, Sparkles,
} from 'lucide-react';
import { PageHeader } from '../components/layout';
import { Badge, Button, Card, ErrorState, RiskBadge, SeverityBadge, StatusBadge, TableSkeleton } from '../components/ui';
import { Donut, RankBars, RiskGauge, Sparkline, TrendChart } from '../components/charts';
import { useApi, useEventStream } from '../lib/hooks';
import { MetricCard } from '../components/design';
import { formatNumber, timeAgo } from '../lib/format';
import { useAuth } from '../lib/auth';

type Summary = {
  kpis: Record<string, number | null>;
  severity: Record<string, number>;
  incidentStatus: Record<string, number>;
  detectionStatus: Record<string, number>;
  topAssets: { id: string; name: string; hostname: string; criticality: string; risk_score: number; status: string }[];
  recentEvents: { id: string; title: string; event_type: string; severity: string; source: string; occurred_at: string; asset: string | null }[];
  topSources: { source: string; c: number }[];
  openIncidents: { id: string; ref: string; title: string; severity: string; status: string; detected_at: string; assignee: string | null }[];
  generatedAt: string;
};

type Trend = { day: string; events: number; highSeverity: number; incidents: number; detections: number; avgRisk: number; bytesOut: number; flows: number };

type DetectionRow = {
  id: string;
  title: string;
  severity: string;
  riskScore: number;
  status: string;
  detectedAt: string;
  assetHostname: string | null;
};

export default function OverviewPage() {
  const { user } = useAuth();
  const summary = useApi<Summary>('/overview/summary');
  const trends = useApi<Trend[]>('/overview/trends?days=14');
  const detections = useApi<{ data: DetectionRow[] }>('/detections?limit=5');
  const live = useEventStream(() => {}, true);

  if (summary.error) return <><PageHeader title={`Good to see you, ${user?.name?.split(' ')[0] ?? 'analyst'}`} /><Card><ErrorState message={summary.error} onRetry={summary.refresh} /></Card></>;

  const k = summary.data?.kpis ?? {};
  const sev = summary.data?.severity ?? {};
  const totalSev = Object.values(sev).reduce((a, b) => a + b, 0);

  return (
    <>
      <PageHeader
        title={`Good to see you, ${user?.name?.split(' ')[0] ?? 'analyst'}`}
        subtitle="Posture across the last 24 hours, with the queue that needs a decision. Every figure is read from the workspace database."
        actions={<>
          <Link to="/simulations" className="btn"><FlaskConical size={14} aria-hidden="true" /> Run a simulation</Link>
          <Link to="/reports" className="btn btn-primary"><Sparkles size={14} aria-hidden="true" /> Generate report</Link>
        </>}
      />

      {summary.loading || !summary.data ? (
        <div className="grid grid-4">{Array.from({ length: 4 }).map((_, i) => <div className="card kpi" key={i}><div className="skeleton" style={{ height: 12, width: '50%' }} /><div className="skeleton" style={{ height: 26, width: '35%', marginTop: 12 }} /></div>)}</div>
      ) : (
        <div className="grid grid-4">
          <MetricCard label="Security events · 24h" value={k.events24h ?? 0} icon={<Activity size={12} aria-hidden="true" />}
            foot={<><span style={{ color: 'var(--color-error)' }}>{formatNumber(k.criticalEvents)} critical</span> · {formatNumber(k.highSeverityEvents)} high or critical of {formatNumber(k.eventsTotal)} total</>}
            spark={<Sparkline values={(trends.data ?? []).slice(-14).map((t) => t.events)} />} />
          <MetricCard label="Open incidents" value={k.incidentsOpen ?? 0} icon={<Siren size={12} aria-hidden="true" />}
            foot={<>{formatNumber(k.criticalIncidents)} critical · {formatNumber(k.incidents7d)} opened this week</>} />
          <MetricCard label="Open detections" value={k.detectionsOpen ?? 0} icon={<Radar size={12} aria-hidden="true" />}
            foot={<><span style={{ color: 'var(--color-warning)' }}>{formatNumber(k.detectionsHighRisk)} at risk ≥ 70</span> awaiting triage</>} />
          <MetricCard label="Assets at risk" value={`${formatNumber(k.assetsAtRisk)} / ${formatNumber(k.assetsTotal)}`} icon={<Server size={12} aria-hidden="true" />}
            foot={<>Mean risk {k.avgAssetRisk ?? 0}/100 · {formatNumber(k.criticalAssets)} critical assets</>} />
        </div>
      )}

      <div className="grid grid-2" style={{ marginTop: 14, gridTemplateColumns: '1.55fr 1fr' }}>
        <Card title="Event volume and high severity load" subtitle="Last 14 days"
          actions={<Badge tone="neutral">Deterministic counts</Badge>}>
          {trends.loading ? <div className="skeleton" style={{ height: 210 }} /> : trends.error ? <ErrorState message={trends.error} onRetry={trends.refresh} /> : (
            <TrendChart
              data={trends.data ?? []}
              series={[
                { key: 'events', label: 'All events', color: 'var(--color-mint)' },
                { key: 'highSeverity', label: 'High and critical', color: 'var(--color-orange)' },
                { key: 'detections', label: 'Detections', color: 'var(--color-info-text)' },
              ]}
              height={224}
            />
          )}
        </Card>

        <Card title="Severity mix" subtitle="Events in the last 7 days"
          actions={<span className="tiny faint">{formatNumber(totalSev)} events</span>}>
          <Donut
            centerValue={formatNumber(totalSev)}
            centerLabel="EVENTS · 7D"
            segments={[
              { label: 'critical', value: sev.critical ?? 0, color: 'var(--color-red)' },
              { label: 'high', value: sev.high ?? 0, color: 'var(--color-orange)' },
              { label: 'medium', value: sev.medium ?? 0, color: 'var(--color-amber)' },
              { label: 'low', value: sev.low ?? 0, color: 'var(--color-info-text)' },
              { label: 'info', value: sev.info ?? 0, color: 'var(--color-neutral-text)' },
            ]}
          />
          <div className="divider" style={{ margin: '14px 0 12px' }} />
          <div className="row-between">
            <div>
              <p className="tiny faint">Mean simulated risk</p>
              <p className="strong" style={{ fontSize: 18 }}>{k.meanSimulatedRisk ?? 0}<span className="tiny faint">/100</span></p>
            </div>
            <div className="right">
              <p className="tiny faint">Simulations completed</p>
              <p className="strong" style={{ fontSize: 18 }}>{formatNumber(k.simulationsCompleted)}<span className="tiny faint">/{formatNumber(k.simulations)}</span></p>
            </div>
            <Link to="/simulations" className="btn btn-sm">Open lab <ArrowUpRight size={13} aria-hidden="true" /></Link>
          </div>
        </Card>
      </div>

      <div className="grid grid-2" style={{ marginTop: 14, gridTemplateColumns: '1.25fr 1fr' }}>
        <Card title="Incidents needing a decision" subtitle="Highest severity first" reveal
          actions={<Link to="/incidents" className="btn btn-sm btn-ghost">All incidents <ArrowUpRight size={13} aria-hidden="true" /></Link>}
          bodyClass="">
          {summary.loading ? <TableSkeleton rows={4} cols={4} /> : (summary.data?.openIncidents.length ?? 0) === 0 ? (
            <div className="empty"><CheckCircle2 size={22} color="var(--color-mint)" aria-hidden="true" /><p className="empty-title" style={{ marginTop: 8 }}>Queue is clear</p><p className="empty-body">No incident is waiting for triage.</p></div>
          ) : (
            <div>
              {summary.data?.openIncidents.map((incident) => (
                <Link key={incident.id} to={`/incidents/${incident.id}`} className="row" style={{ padding: '12px 16px', borderBottom: '1px solid var(--color-callout)', gap: 12 }}>
                  <SeverityBadge severity={incident.severity} />
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <p className="truncate-cell" style={{ fontWeight: 550, fontSize: 13 }}>{incident.title}</p>
                    <p className="tiny faint">{incident.ref} · {incident.assignee ?? 'Unassigned'} · {timeAgo(incident.detected_at)}</p>
                  </div>
                  <StatusBadge status={incident.status} />
                </Link>
              ))}
            </div>
          )}
        </Card>

        <Card title="Asset risk" subtitle="Highest scoring assets" reveal revealDelay={40} actions={<Link to="/assets" className="btn btn-sm btn-ghost">Inventory <ArrowUpRight size={13} aria-hidden="true" /></Link>}>
          <div className="stack" style={{ gap: 12 }}>
            {(summary.data?.topAssets ?? []).map((asset) => (
              <div key={asset.id} className="row" style={{ gap: 12 }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <p style={{ fontSize: 12.8, fontWeight: 550 }} className="truncate-cell">{asset.name}</p>
                  <p className="tiny faint mono">{asset.hostname} · {asset.criticality}</p>
                </div>
                <div style={{ width: 90 }}>
                  <div className="bar-track"><div className="bar-fill" style={{ width: `${asset.risk_score}%`, background: asset.risk_score >= 70 ? 'var(--color-red)' : asset.risk_score >= 40 ? 'var(--color-amber)' : 'var(--color-mint)' }} /></div>
                </div>
                <RiskBadge score={asset.risk_score} />
              </div>
            ))}
            {(summary.data?.topAssets.length ?? 0) === 0 && <p className="small faint">No assets yet.</p>}
          </div>
          <div className="divider" style={{ margin: '16px 0 14px' }} />
          <div className="row" style={{ gap: 18, alignItems: 'flex-start' }}>
            <RiskGauge score={k.meanSimulatedRisk ?? 0} />
            <div>
              <p className="tiny faint">Mean simulated risk across completed runs</p>
              <p className="small muted" style={{ marginTop: 4 }}>
                Simulation outcomes are synthetic. They show how the scenario behaved in the engine, not what is happening on your network.
              </p>
            </div>
          </div>
        </Card>
      </div>

      <div className="grid grid-2" style={{ marginTop: 14, gridTemplateColumns: '1.4fr 1fr' }}>
        <Card title="Recent detections" subtitle="Newest rule matches, with the stored risk score" bodyClass="" reveal revealDelay={80}
          actions={<Link to="/detections" className="btn btn-sm btn-ghost">Detection queue <ArrowUpRight size={13} aria-hidden="true" /></Link>}>
          {detections.loading ? <TableSkeleton rows={4} cols={3} /> : detections.error ? (
            <ErrorState message={detections.error} onRetry={detections.refresh} />
          ) : (detections.data?.data.length ?? 0) === 0 ? (
            <div className="empty">
              <CheckCircle2 size={22} color="var(--color-success)" aria-hidden="true" />
              <p className="empty-title" style={{ marginTop: 8 }}>No detections</p>
              <p className="empty-body">Rules have not matched any event yet.</p>
            </div>
          ) : (
            <div>
              {detections.data?.data.map((detection) => (
                <Link key={detection.id} to="/detections" className="row" style={{ padding: '12px 16px', borderBottom: '1px solid var(--color-border)', gap: 12 }}>
                  <SeverityBadge severity={detection.severity} />
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <p className="truncate-cell" style={{ fontWeight: 550, fontSize: 13 }}>{detection.title}</p>
                    <p className="tiny faint">{detection.assetHostname ?? 'Unassigned asset'} · {timeAgo(detection.detectedAt)}</p>
                  </div>
                  <RiskBadge score={detection.riskScore} />
                </Link>
              ))}
            </div>
          )}
        </Card>

        <Card title="Monitoring status" subtitle="Connection and newest signal" reveal>
          <div className="stack" style={{ gap: 12 }}>
            <div className="row-between">
              <span className="small muted">Event stream</span>
              <Badge tone={live ? 'mint' : 'neutral'} dot>{live ? 'Connected' : 'Offline'}</Badge>
            </div>
            <div className="row-between">
              <span className="small muted">Newest event</span>
              <span className="small">{summary.data?.recentEvents[0] ? timeAgo(summary.data.recentEvents[0].occurred_at) : 'No events yet'}</span>
            </div>
            <div className="row-between">
              <span className="small muted">Sources reporting</span>
              <span className="small">{summary.data?.topSources.length ?? 0}</span>
            </div>
            <div className="row-between">
              <span className="small muted">Events, 24 hours</span>
              <span className="small">{formatNumber(k.events24h)}</span>
            </div>
          </div>
          <p className="tiny faint" style={{ marginTop: 12 }}>
            The stream pushes new events to this page. If it is offline, figures still load from the API on navigation and refresh.
          </p>
        </Card>
      </div>

      <div className="grid grid-2" style={{ marginTop: 14, gridTemplateColumns: '1.4fr 1fr' }}>
        <Card title="Recent telemetry" subtitle="Newest events across every source" bodyClass="" reveal revealDelay={40} actions={<Link to="/monitoring" className="btn btn-sm btn-ghost">Monitoring <ArrowUpRight size={13} aria-hidden="true" /></Link>}>
          {summary.loading ? <TableSkeleton rows={6} cols={4} /> : (
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>Severity</th><th>Event</th><th>Source</th><th>Asset</th><th className="right">When</th></tr></thead>
                <tbody>
                  {(summary.data?.recentEvents ?? []).map((event) => (
                    <tr key={event.id}>
                      <td><SeverityBadge severity={event.severity} /></td>
                      <td>
                        <p className="truncate-cell" style={{ maxWidth: 300 }}>{event.title}</p>
                        <p className="tiny faint mono">{event.event_type}</p>
                      </td>
                      <td className="muted small">{event.source}</td>
                      <td className="mono muted">{event.asset ?? '—'}</td>
                      <td className="right tiny faint">{timeAgo(event.occurred_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <Card title="Signal sources" subtitle="Share of events in the last 7 days">
          <RankBars items={(summary.data?.topSources ?? []).map((s) => ({ label: s.source, value: s.c }))} color="var(--color-info-text)" />
          <div className="divider" style={{ margin: '16px 0 14px' }} />
          <div className="stack" style={{ gap: 9 }}>
            <div className="row-between">
              <span className="small muted row" style={{ gap: 6 }}><AlertTriangle size={13} aria-hidden="true" /> Open vulnerabilities</span>
              <span className="strong">{formatNumber(k.vulnerabilitiesOpen)}</span>
            </div>
            <div className="row-between">
              <span className="small muted row" style={{ gap: 6 }}><Radar size={13} aria-hidden="true" /> Critical CVEs open</span>
              <span className="strong" style={{ color: 'var(--color-danger-text-2)' }}>{formatNumber(k.criticalVulns)}</span>
            </div>
            <div className="row-between">
              <span className="small muted row" style={{ gap: 6 }}><Activity size={13} aria-hidden="true" /> Mean time to resolve</span>
              <span className="strong">{k.mttrHours !== null && k.mttrHours !== undefined ? `${k.mttrHours}h` : 'No resolved incidents yet'}</span>
            </div>
          </div>
        </Card>
      </div>

      <Card title="How this page gets its numbers" subtitle="No estimated figures" className="" bodyClass="card-body" >
        <p className="small muted">
          Counts are SQL aggregates over the workspace tables, scoped to your organization. Detections come from deterministic rules evaluated at
          ingest time and on demand; each detection stores its scoring factors. Simulation scores are produced by the native engine and are labelled
          synthetic everywhere they appear.
        </p>
        <div className="row" style={{ marginTop: 12, gap: 8, flexWrap: 'wrap' }}>
          <Link to="/detections" className="btn btn-sm">Detection queue</Link>
          <Link to="/reports" className="btn btn-sm">Build a report</Link>
          <Link to="/network" className="btn btn-sm">Network flows</Link>
        </div>
      </Card>
    </>
  );
}
