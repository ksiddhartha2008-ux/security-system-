import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, Download, Play, Square, Trash2 } from 'lucide-react';
import {
  Badge, Button, Card, ConfirmDialog, ErrorState, KeyValue, Progress, RiskBadge, SeverityBadge,
  StatusBadge, TableSkeleton, useToast, InlineNotice,
} from '../components/ui';
import { RiskGauge } from '../components/charts';
import { useApi } from '../lib/hooks';
import { api, download, ApiError } from '../lib/api';
import { formatDate, titleCase } from '../lib/format';
import { useAuth } from '../lib/auth';

type Detail = {
  id: string; ref: string; name: string; scenario: string; scenarioName: string; status: string; engine: string;
  config: Record<string, unknown>; progress: number; currentRound: number; totalRounds: number;
  riskScore: number | null; summary: {
    metrics?: Record<string, number | string | boolean>;
    findings?: string[]; worstSeverity?: string; eventCount?: number; synthetic?: boolean;
  };
  error: string | null; synthetic: boolean; disclaimer: string; createdAt: string; startedAt: string | null; finishedAt: string | null;
  agents: { id: string; name: string; role: string; persona: string; status: string; riskScore: number; activityCount: number; lastAction: string | null }[];
  events: { id: string; round: number; agentId: string | null; type: string; severity: string; message: string; metadata: Record<string, unknown>; occurredAt: string }[];
  report: { id: string; riskScore: number; findings: string[]; recommendations: string[]; narrative: string; createdAt: string } | null;
};

export default function SimulationDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { permissions } = useAuth();
  const toast = useToast();
  const simulation = useApi<Detail>(id ? `/simulations/${id}` : null);
  const [busy, setBusy] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const status = simulation.data?.status;

  useEffect(() => {
    if (status !== 'running' && status !== 'queued') return undefined;
    const timer = setInterval(() => simulation.refresh(), 1600);
    return () => clearInterval(timer);
  }, [status, simulation.refresh]);

  if (simulation.loading && !simulation.data) return <Card><TableSkeleton rows={10} cols={3} /></Card>;
  if (simulation.error) return <Card><ErrorState message={simulation.error} onRetry={simulation.refresh} /></Card>;
  if (!simulation.data) return null;
  const sim = simulation.data;
  const metrics = sim.summary.metrics ?? {};
  const agentName = (agentId: string | null) => sim.agents.find((a) => a.id === agentId)?.name ?? 'system';

  const start = async () => {
    setBusy(true);
    try {
      await api.post(`/simulations/${sim.id}/start`);
      toast.push('success', 'Simulation started', 'Rounds run in the background. This page updates as events arrive.');
      simulation.refresh();
    } catch (err) { toast.push('error', 'Could not start', err instanceof ApiError ? err.message : undefined); }
    finally { setBusy(false); }
  };

  const cancel = async () => {
    setBusy(true);
    try {
      await api.post(`/simulations/${sim.id}/cancel`);
      toast.push('warn', 'Run cancelled');
      simulation.refresh();
    } catch (err) { toast.push('error', 'Could not cancel', err instanceof ApiError ? err.message : undefined); }
    finally { setBusy(false); }
  };

  const remove = async () => {
    setBusy(true);
    try {
      await api.del(`/simulations/${sim.id}`);
      toast.push('success', 'Simulation deleted');
      navigate('/simulations');
    } catch (err) { toast.push('error', 'Could not delete', err instanceof ApiError ? err.message : undefined); }
    finally { setBusy(false); setConfirmDelete(false); }
  };

  return (
    <>
      <div className="row" style={{ marginBottom: 12 }}>
        <Button size="sm" variant="ghost" onClick={() => navigate('/simulations')} icon={<ArrowLeft size={14} aria-hidden="true" />}>Simulation lab</Button>
        <span className="mono tiny faint">{sim.ref}</span>
      </div>

      <div className="page-head">
        <div>
          <div className="row wrap" style={{ gap: 8 }}>
            <StatusBadge status={sim.status} />
            <Badge tone="neutral">{sim.scenarioName}</Badge>
            <Badge tone={sim.engine === 'mirofish' ? 'purple' : 'neutral'}>{sim.engine}</Badge>
            <Badge tone="amber">synthetic</Badge>
          </div>
          <h1 className="page-title" style={{ marginTop: 8 }}>{sim.name}</h1>
          <p className="page-sub">Created {formatDate(sim.createdAt)}{sim.finishedAt ? ` · finished ${formatDate(sim.finishedAt)}` : ''}</p>
        </div>
        <div className="page-actions">
          {permissions.canWrite && ['draft', 'failed', 'cancelled'].includes(sim.status) && (
            <Button variant="primary" icon={<Play size={14} aria-hidden="true" />} onClick={start} loading={busy}>Start run</Button>
          )}
          {permissions.canWrite && sim.status === 'running' && (
            <Button variant="danger" icon={<Square size={13} aria-hidden="true" />} onClick={cancel} loading={busy}>Cancel run</Button>
          )}
          {sim.report && (
            <Button icon={<Download size={14} aria-hidden="true" />} onClick={() => download(`/simulations/${sim.id}/report/download`, `${sim.ref}-report.md`).catch((err) => toast.push('error', 'Download failed', err.message))}>Download report</Button>
          )}
          {permissions.canAdmin && sim.status !== 'running' && (
            <Button variant="ghost" icon={<Trash2 size={14} aria-hidden="true" />} onClick={() => setConfirmDelete(true)} aria-label="Delete simulation" />
          )}
        </div>
      </div>

      {sim.error && <InlineNotice tone="error">{sim.error}</InlineNotice>}
      {sim.summary.synthetic === false && <InlineNotice tone="warn">This record is not marked synthetic.</InlineNotice>}

      <div className="grid" style={{ gridTemplateColumns: '1.6fr 1fr', marginBottom: 14 }}>
        <Card title="Run progress" subtitle={`Round ${sim.currentRound} of ${sim.totalRounds}`}
          actions={sim.status === 'running' ? <Badge tone="low" dot>running</Badge> : <Badge tone="neutral">{sim.progress}%</Badge>}>
          <Progress value={sim.progress} label={`${sim.progress}% complete`} />
          <div className="grid grid-3" style={{ marginTop: 16 }}>
            <div><p className="tiny faint">Engine</p><p className="small strong">{sim.engine}</p></div>
            <div><p className="tiny faint">Events generated</p><p className="small strong">{sim.events.length}</p></div>
            <div><p className="tiny faint">Worst severity</p><p className="small strong" style={{ textTransform: 'capitalize' }}>{sim.summary.worstSeverity ?? '—'}</p></div>
          </div>
          {Object.keys(metrics).length > 0 && (
            <>
              <div className="divider" style={{ margin: '16px 0' }} />
              <p className="label" style={{ marginBottom: 8 }}>Outcome metrics</p>
              <div className="grid grid-3" style={{ gap: 10 }}>
                {Object.entries(metrics).map(([key, value]) => (
                  <div key={key}>
                    <p className="tiny faint">{titleCase(key)}</p>
                    <p className="small strong">{typeof value === 'boolean' ? (value ? 'yes' : 'no') : String(value)}</p>
                  </div>
                ))}
              </div>
            </>
          )}
        </Card>

        <Card title="Simulated risk" subtitle="Deterministic score from the run outcome">
          <div className="row" style={{ justifyContent: 'center' }}>
            <RiskGauge score={sim.riskScore} size={190} />
          </div>
          <p className="small muted" style={{ textAlign: 'center', marginTop: 8 }}>
            {sim.riskScore === null ? 'The run has not produced a score yet.' : 'Higher means the scenario caused more impact before containment.'}
          </p>
          <div className="divider" style={{ margin: '14px 0' }} />
          <KeyValue items={[
            { label: 'Started', value: sim.startedAt ? formatDate(sim.startedAt) : 'Not started' },
            { label: 'Finished', value: sim.finishedAt ? formatDate(sim.finishedAt) : '—' },
            { label: 'Agents', value: String(sim.agents.length) },
          ]} />
        </Card>
      </div>

      <div className="grid" style={{ gridTemplateColumns: '1fr 1fr', marginBottom: 14 }}>
        <Card title="Findings" subtitle="Generated from this run only">
          {sim.report ? (
            <ul className="small" style={{ margin: 0, paddingLeft: 18, display: 'grid', gap: 8, color: '#c3d2df' }}>
              {sim.report.findings.map((finding) => <li key={finding}>{finding}</li>)}
            </ul>
          ) : <p className="small faint">Findings appear after the run completes.</p>}
        </Card>
        <Card title="Recommendations" subtitle="Controls to test next">
          {sim.report ? (
            <ul className="small" style={{ margin: 0, paddingLeft: 18, display: 'grid', gap: 8, color: '#c3d2df' }}>
              {sim.report.recommendations.map((rec) => <li key={rec}>{rec}</li>)}
            </ul>
          ) : <p className="small faint">Recommendations appear after the run completes.</p>}
        </Card>
      </div>

      <Card title="Agents" subtitle="Each agent acts on synthetic data only" bodyClass="">
        <div className="table-wrap">
          <table className="data">
            <thead><tr><th>Agent</th><th>Role</th><th className="hide-sm">Persona</th><th>Actions</th><th>Risk</th><th>Last action</th></tr></thead>
            <tbody>
              {sim.agents.map((agent) => (
                <tr key={agent.id}>
                  <td className="mono tiny">{agent.name}</td>
                  <td><Badge tone={agent.role === 'attacker' || agent.role === 'insider' ? 'critical' : agent.role === 'defender' ? 'mint' : 'neutral'}>{agent.role}</Badge></td>
                  <td className="small muted hide-sm" style={{ maxWidth: 330 }}>{agent.persona}</td>
                  <td className="num">{agent.activityCount}</td>
                  <td><RiskBadge score={agent.riskScore} /></td>
                  <td className="tiny muted truncate-cell" style={{ maxWidth: 300 }}>{agent.lastAction ?? 'No action yet'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title="Simulation events" subtitle={`${sim.events.length} events across ${sim.currentRound} round(s)`} bodyClass="" className="">
        <div className="table-wrap" style={{ maxHeight: 460, overflowY: 'auto' }}>
          <table className="data">
            <thead><tr><th>Round</th><th>Severity</th><th>Agent</th><th>Event</th><th>Detail</th></tr></thead>
            <tbody>
              {sim.events.map((event) => (
                <tr key={event.id}>
                  <td className="num tiny">{event.round}</td>
                  <td><SeverityBadge severity={event.severity} /></td>
                  <td className="mono tiny muted">{agentName(event.agentId)}</td>
                  <td className="mono tiny">{event.type}</td>
                  <td className="small" style={{ maxWidth: 560 }}>{event.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {sim.events.length === 0 && <p className="empty-body" style={{ padding: 20 }}>No events yet. Start the run to generate them.</p>}
      </Card>

      {sim.report && (
        <Card title="Simulation report" subtitle={`Generated ${formatDate(sim.report.createdAt)}`} className="" >
          <p className="small" style={{ color: '#c3d2df', lineHeight: 1.7 }}>{sim.report.narrative}</p>
          <div className="row" style={{ marginTop: 12, gap: 8, flexWrap: 'wrap' }}>
            <Button size="sm" onClick={() => download(`/simulations/${sim.id}/report/download`, `${sim.ref}-report.md`).catch((err) => toast.push('error', 'Download failed', err.message))} icon={<Download size={13} aria-hidden="true" />}>Download Markdown</Button>
            <Link to="/reports" className="btn btn-sm">Include in a report</Link>
          </div>
        </Card>
      )}

      <p className="tiny faint" style={{ marginTop: 16 }}>{sim.disclaimer}</p>

      <ConfirmDialog open={confirmDelete} title="Delete this simulation?" body="The run, its agents, events and report will be removed from the workspace. This cannot be undone."
        confirmLabel="Delete run" destructive loading={busy} onConfirm={remove} onClose={() => setConfirmDelete(false)} />
    </>
  );
}

