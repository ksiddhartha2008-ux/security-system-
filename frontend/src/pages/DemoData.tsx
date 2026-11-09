import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Database, Play, RefreshCw, ShieldAlert, Trash2 } from 'lucide-react';
import { PageHeader } from '../components/layout';
import {
  Badge, Button, Card, ErrorState, Field, KeyValue, Modal, TableSkeleton, useToast,
} from '../components/ui';
import { useApi } from '../lib/hooks';
import { api, ApiError } from '../lib/api';
import { formatDate, timeAgo } from '../lib/format';
import { useAuth } from '../lib/auth';

type Counts = Record<string, number>;
type DemoStatus = {
  counts: {
    assets: Counts; events: Counts; detections: Counts; incidents: Counts;
    vulnerabilities: Counts; networkEvents: Counts;
  };
  hasDemoData: boolean;
  batchId: string | null;
  runs: { id: string; action: string; batchId: string | null; counts: Counts; createdAt: string }[];
};
type Scenario = { key: string; name: string; summary: string; defaultRounds: number; agents: { name: string }[] };

const DEMO_KEYS = ['brute-force', 'phishing', 'malware', 'sql-injection', 'suspicious-admin'];

export default function DemoDataPage() {
  const { permissions } = useAuth();
  const toast = useToast();
  const navigate = useNavigate();
  const status = useApi<DemoStatus>('/demo/status');
  const scenarios = useApi<Scenario[]>('/simulations/scenarios');
  const [busy, setBusy] = useState<string | null>(null);
  const [resetOpen, setResetOpen] = useState(false);
  const [confirmText, setConfirmText] = useState('');

  const generate = async () => {
    setBusy('generate');
    try {
      const result = await api.post<{ counts: Counts }>('/demo/generate');
      toast.push('success', 'Demo data generated', `${result.counts.events} events, ${result.counts.incidents} incidents.`);
      status.refresh();
    } catch (err) {
      toast.push('error', 'Generation failed', err instanceof ApiError ? err.message : undefined);
    } finally { setBusy(null); }
  };

  const reset = async () => {
    setBusy('reset');
    try {
      const result = await api.post<{ deleted: Counts; nothingToDo: boolean }>('/demo/reset', { confirm: confirmText });
      toast.push('success', result.nothingToDo ? 'No demo data to remove' : 'Demo data removed', 'Real and simulated records were preserved.');
      setResetOpen(false);
      setConfirmText('');
      status.refresh();
    } catch (err) {
      toast.push('error', 'Reset failed', err instanceof ApiError ? err.message : undefined);
    } finally { setBusy(null); }
  };

  const runScenario = async (key: string) => {
    setBusy(key);
    try {
      const result = await api.post<{ id: string; ref: string }>(`/demo/scenarios/${key}/run`);
      toast.push('success', `Scenario started (${result.ref})`, 'Events feed the detection engine as they run.');
      navigate(`/simulations/${result.id}`);
    } catch (err) {
      toast.push('error', 'Scenario failed to start', err instanceof ApiError ? err.message : undefined);
    } finally { setBusy(null); }
  };

  const runAll = async () => {
    setBusy('all');
    try {
      const result = await api.post<{ runs: { ref: string }[] }>('/demo/scenarios/run-all');
      toast.push('success', `${result.runs.length} scenarios started`, 'Open the simulation lab to watch them run.');
      navigate('/simulations');
    } catch (err) {
      toast.push('error', 'Could not start scenarios', err instanceof ApiError ? err.message : undefined);
    } finally { setBusy(null); }
  };

  if (status.error) return <><PageHeader title="Demo data" /><Card><ErrorState message={status.error} onRetry={status.refresh} /></Card></>;

  const data = status.data;
  const demoEvents = data?.counts.events.DEMO ?? 0;
  const simEvents = data?.counts.events.SIMULATED ?? 0;
  const canonical = (scenarios.data ?? []).filter((scenario) => DEMO_KEYS.includes(scenario.key));

  return (
    <>
      <PageHeader
        title="Demo data"
        subtitle="Generate a realistic synthetic workspace through the same event, detection and incident pipeline the application uses for real telemetry."
        actions={<>
          <Button icon={<RefreshCw size={14} aria-hidden="true" />} onClick={() => status.refresh()}>Refresh</Button>
          {permissions.canAdmin && (
            <Button variant="danger" icon={<Trash2 size={14} aria-hidden="true" />} onClick={() => setResetOpen(true)} disabled={!data?.hasDemoData}>Reset demo data</Button>
          )}
          {permissions.canAdmin && (
            <Button variant="primary" icon={<Database size={14} aria-hidden="true" />} onClick={generate} loading={busy === 'generate'} disabled={Boolean(data?.hasDemoData)}>
              {data?.hasDemoData ? 'Demo batch present' : 'Generate demo data'}
            </Button>
          )}
        </>}
      />

      {!permissions.canAdmin && (
        <div className="notice" style={{ marginBottom: 14 }}>
          Only an administrator can generate or reset demo data. You can still inspect the counts below.
        </div>
      )}

      {status.loading && !data ? <Card><TableSkeleton rows={6} cols={3} /></Card> : data && (
        <>
          <div className="grid grid-4" style={{ marginBottom: 14 }}>
            {[
              { key: 'assets', label: 'Assets' },
              { key: 'events', label: 'Security events' },
              { key: 'detections', label: 'Detections' },
              { key: 'incidents', label: 'Incidents' },
            ].map((item) => {
              const counts = data.counts[item.key as keyof DemoStatus['counts']] as Counts;
              const total = Object.values(counts).reduce((sum, value) => sum + value, 0);
              return (
                <div className="card kpi" key={item.key}>
                  <div className="kpi-label">{item.label}</div>
                  <div className="kpi-value">{total}</div>
                  <div className="kpi-foot">
                    <Badge tone="amber">demo {counts.DEMO ?? 0}</Badge>
                    <Badge tone="low">sim {counts.SIMULATED ?? 0}</Badge>
                    <span className="tiny faint">real {counts.REAL ?? 0}</span>
                  </div>
                </div>
              );
            })}
          </div>

          <div className="grid" style={{ gridTemplateColumns: '1.3fr 1fr', marginBottom: 14 }}>
            <Card title="What generation does" subtitle="Deterministic and reproducible"
              actions={<Badge tone={data.hasDemoData ? 'mint' : 'neutral'}>{data.hasDemoData ? 'batch present' : 'empty'}</Badge>}>
              <p className="small muted">
                Creates 45 assets, about 250 security events across ten event classes, network telemetry, 14 vulnerability
                records, then runs the deterministic rules and correlates high risk detections into incidents. Nothing is
                written directly to a dashboard counter.
              </p>
              <div className="divider" style={{ margin: '14px 0' }} />
              <KeyValue items={[
                { label: 'Batch', value: <span className="mono">{data.batchId ?? 'none'}</span> },
                { label: 'Demo events', value: String(demoEvents) },
                { label: 'Simulated events', value: String(simEvents) },
                { label: 'Demo incidents', value: String(data.counts.incidents.DEMO ?? 0) },
                { label: 'Demo vulnerabilities', value: String(data.counts.vulnerabilities.DEMO ?? 0) },
                { label: 'Network flows', value: String(data.counts.networkEvents.DEMO ?? 0) },
              ]} />
              <div className="row wrap" style={{ marginTop: 14, gap: 8 }}>
                <Button size="sm" onClick={() => navigate('/overview')}>Open dashboard</Button>
                <Button size="sm" variant="ghost" onClick={() => navigate('/monitoring')}>Inspect events</Button>
                <Button size="sm" variant="ghost" onClick={() => navigate('/incidents')}>Incident queue</Button>
              </div>
            </Card>

            <Card title="Data classification" subtitle="Every record carries an origin">
              <div className="stack" style={{ gap: 10 }}>
                <div className="row" style={{ gap: 8 }}><Badge tone="amber" dot>demo</Badge><span className="small muted">Synthetic workspace data generated here or by the seeder.</span></div>
                <div className="row" style={{ gap: 8 }}><Badge tone="low" dot>simulated</Badge><span className="small muted">Events emitted by the Threat Simulation Lab, fed through detection.</span></div>
                <div className="row" style={{ gap: 8 }}><Badge tone="neutral">real</Badge><span className="small muted">Telemetry you ingested yourself. Never removed by a demo reset.</span></div>
              </div>
              <div className="divider" style={{ margin: '14px 0' }} />
              <p className="tiny faint">
                A reset deletes only records tagged DEMO for this organization. Real events, incidents, evidence and
                simulated runs are preserved.
              </p>
            </Card>
          </div>

          <Card title="Run a scenario" subtitle="Each scenario feeds the event pipeline, then detection and correlation"
            actions={<Button size="sm" variant="primary" icon={<Play size={13} aria-hidden="true" />} onClick={runAll} loading={busy === 'all'} disabled={!permissions.canAdmin}>Run all five</Button>}>
            <div className="grid grid-2">
              {canonical.map((scenario) => (
                <div key={scenario.key} className="row" style={{ gap: 10, alignItems: 'flex-start', padding: '10px 12px', border: '1px solid var(--color-line)', borderRadius: 9 }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div className="row" style={{ gap: 8 }}><span className="strong small">{scenario.name}</span><Badge tone="neutral">{scenario.defaultRounds} rounds</Badge></div>
                    <p className="tiny faint" style={{ marginTop: 4 }}>{scenario.summary}</p>
                  </div>
                  <Button size="sm" onClick={() => runScenario(scenario.key)} loading={busy === scenario.key} disabled={!permissions.canAdmin || busy !== null}>Run</Button>
                </div>
              ))}
            </div>
          </Card>

          <Card title="Seed history" subtitle="Generate and reset actions for this workspace" bodyClass="" className="">
            {data.runs.length === 0 ? (
              <p className="empty-body" style={{ padding: 20 }}>No demo runs yet. Generate a batch to populate the dashboard.</p>
            ) : (
              <div className="table-wrap">
                <table className="data">
                  <thead><tr><th>Action</th><th>Batch</th><th>Records</th><th className="right">When</th></tr></thead>
                  <tbody>
                    {data.runs.map((run) => (
                      <tr key={run.id}>
                        <td><Badge tone={run.action === 'generate' ? 'mint' : 'high'}>{run.action}</Badge></td>
                        <td className="mono tiny">{run.batchId ?? '—'}</td>
                        <td className="tiny muted">
                          {Object.entries(run.counts).filter(([, value]) => typeof value === 'number' && value > 0).slice(0, 4).map(([key, value]) => `${key} ${value}`).join(' · ')}
                        </td>
                        <td className="right tiny faint" title={formatDate(run.createdAt)}>{timeAgo(run.createdAt)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </>
      )}

      <Modal open={resetOpen} onClose={() => { setResetOpen(false); setConfirmText(''); }} title="Reset demo data"
        subtitle="Only records tagged DEMO in this organization are deleted."
        footer={<>
          <Button variant="ghost" onClick={() => { setResetOpen(false); setConfirmText(''); }}>Cancel</Button>
          <Button variant="danger" onClick={reset} loading={busy === 'reset'} disabled={confirmText !== 'RESET'}>Delete demo data</Button>
        </>}>
        <div className="notice">
          <ShieldAlert size={14} aria-hidden="true" style={{ display: 'inline', marginRight: 6 }} />
          Demo assets, events, detections, incidents, vulnerabilities and network flows will be removed. Real telemetry and simulated runs stay.
        </div>
        <Field label="Type RESET to confirm" htmlFor="reset-confirm">
          <input id="reset-confirm" className="input mono" value={confirmText} onChange={(event) => setConfirmText(event.target.value)} placeholder="RESET" />
        </Field>
      </Modal>
    </>
  );
}
