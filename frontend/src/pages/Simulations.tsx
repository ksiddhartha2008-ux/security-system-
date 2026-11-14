import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { BrainCircuit, Download, FlaskConical, Play, Plus, ServerCog } from 'lucide-react';
import { PageHeader } from '../components/layout';
import {
  Badge, Button, Card, EmptyState, ErrorState, Field, InlineNotice, Modal, Pagination, Progress,
  RiskBadge, StatusBadge, TableSkeleton, useToast,
} from '../components/ui';
import { useApi } from '../lib/hooks';
import { api, ApiError } from '../lib/api';
import { formatDate, timeAgo, titleCase } from '../lib/format';
import { useAuth } from '../lib/auth';

type Scenario = {
  key: string; name: string; summary: string; category: string; defaultRounds: number;
  defaultConfig: Record<string, number | boolean>; agents: { name: string; role: string; persona: string }[];
};
type Simulation = {
  id: string; ref: string; name: string; scenario: string; status: string; engine: string; progress: number;
  currentRound: number; totalRounds: number; riskScore: number | null; createdBy: string | null;
  createdAt: string; finishedAt: string | null; error: string | null;
};
type MiroStatus = {
  configured: boolean; baseUrl: string | null; reachable: boolean; latencyMs: number | null; reason: string | null;
  license: string; runtime: string; capabilities: { id: string; label: string; endpoint: string }[];
  projects?: number | null;
};

export default function SimulationsPage() {
  const { permissions } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();
  const [page, setPage] = useState(1);
  const [createFor, setCreateFor] = useState<Scenario | null>(null);
  const [importOpen, setImportOpen] = useState(false);

  const scenarios = useApi<Scenario[]>('/simulations/scenarios');
  const runs = useApi<{ data: Simulation[]; meta: { page: number; limit: number; total: number; totalPages: number } }>(`/simulations?page=${page}&limit=15`);
  const miro = useApi<MiroStatus>('/simulations/mirofish/status');

  return (
    <>
      <PageHeader title="Threat simulation lab" subtitle="Rehearse five attack scenarios against synthetic data with a multi agent engine. Runs are labelled synthetic everywhere they appear."
        actions={permissions.canWrite ? <Button variant="primary" icon={<Plus size={14} aria-hidden="true" />} onClick={() => setCreateFor(scenarios.data?.[0] ?? null)} disabled={!scenarios.data?.length}>New simulation</Button> : undefined} />

      <InlineNotice tone="warn">
        Simulations run entirely inside SecureFlow AI on generated data. They do not attack real systems, and outcomes are not predictions or
        production detections. MiroFish, when configured, runs as a separate service and its runs are imported read only.
      </InlineNotice>

      <h2 className="section-title" style={{ marginTop: 22 }}>Scenarios</h2>
      <div className="feature-grid">
        {scenarios.loading && Array.from({ length: 3 }).map((_, i) => <Card key={i}><TableSkeleton rows={3} cols={1} /></Card>)}
        {scenarios.error && <Card><ErrorState message={scenarios.error} onRetry={scenarios.refresh} /></Card>}
        {(scenarios.data ?? []).map((scenario, index) => (
          <Card key={scenario.key} reveal revealDelay={index * 45} title={scenario.name} subtitle={`${titleCase(scenario.category)} · ${scenario.defaultRounds} rounds · ${scenario.agents.length} agents`}
            actions={<Badge tone="mint">synthetic</Badge>}>
            <p className="small muted">{scenario.summary}</p>
            <div className="row wrap" style={{ gap: 4, marginTop: 10 }}>
              {scenario.agents.map((agent) => <span key={agent.name} className="chip">{agent.name}</span>)}
            </div>
            <div className="row" style={{ marginTop: 14, gap: 8 }}>
              <Button size="sm" variant="primary" icon={<Play size={12} aria-hidden="true" />} disabled={!permissions.canWrite} onClick={() => setCreateFor(scenario)}>Configure run</Button>
            </div>
          </Card>
        ))}
      </div>

      <h2 className="section-title">Run history</h2>
      <Card bodyClass="">
        {runs.loading && !runs.data ? <TableSkeleton rows={5} cols={6} /> : runs.error ? <ErrorState message={runs.error} onRetry={runs.refresh} /> : (
          <>
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>Reference</th><th>Run</th><th>Scenario</th><th>Engine</th><th>Status</th><th>Progress</th><th>Risk</th><th className="right">Created</th></tr></thead>
                <tbody>
                  {runs.data?.data.map((run) => (
                    <tr key={run.id} className="row-link" onClick={() => navigate(`/simulations/${run.id}`)} tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter') navigate(`/simulations/${run.id}`); }}>
                      <td className="mono tiny">{run.ref}</td>
                      <td style={{ fontWeight: 550 }}>{run.name}</td>
                      <td className="small muted">{run.scenario.replace(/-/g, ' ')}</td>
                      <td><Badge tone={run.engine === 'mirofish' ? 'purple' : 'neutral'}>{run.engine}</Badge></td>
                      <td><StatusBadge status={run.status} /></td>
                      <td style={{ width: 110 }}>{run.status === 'running' || run.status === 'completed' ? <Progress value={run.progress} /> : <span className="tiny faint">{run.progress}%</span>}</td>
                      <td><RiskBadge score={run.riskScore} /></td>
                      <td className="right tiny faint">{timeAgo(run.createdAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {runs.data?.data.length === 0 && <EmptyState title="No simulation runs yet" body="Pick a scenario above and create your first run. It takes a few seconds." icon={<FlaskConical size={18} aria-hidden="true" />} />}
            {runs.data && runs.data.data.length > 0 && <Pagination page={runs.data.meta.page} totalPages={runs.data.meta.totalPages} total={runs.data.meta.total} onPage={setPage} />}
          </>
        )}
      </Card>

      <h2 className="section-title">MiroFish adapter</h2>
      <Card title="Separate simulation service" subtitle="AGPL-3.0 · Python 3.11 to 3.12 · Flask plus camel-oasis and Zep Cloud"
        actions={<Badge tone={miro.data?.reachable ? 'mint' : miro.data?.configured ? 'critical' : 'neutral'}>{miro.data?.reachable ? 'connected' : miro.data?.configured ? 'error' : 'unconfigured'}</Badge>}>
        {miro.loading ? <TableSkeleton rows={3} cols={1} /> : (
          <div className="stack">
            <p className="small muted">{miro.data?.reason ?? `Reachable in ${miro.data?.latencyMs} ms.`}</p>
            <div className="grid grid-2">
              <div>
                <p className="label" style={{ marginBottom: 6 }}>Documented HTTP capabilities</p>
                <ul className="small muted" style={{ margin: 0, paddingLeft: 16, display: 'grid', gap: 4 }}>
                  {(miro.data?.capabilities ?? []).map((capability) => <li key={capability.id}>{capability.label} <span className="mono tiny faint">{capability.endpoint}</span></li>)}
                </ul>
              </div>
              <div>
                <p className="label" style={{ marginBottom: 6 }}>How this deployment uses it</p>
                <p className="small muted">
                  SecureFlow calls MiroFish over HTTP only when <span className="mono">MIROFISH_BASE_URL</span> is set. A finished MiroFish run can be
                  imported as a read only record. This build never starts a MiroFish run, because that needs an LLM key and a Zep Cloud key.
                </p>
                <div className="row wrap" style={{ gap: 8, marginTop: 10 }}>
                  <Button size="sm" variant="primary" disabled={!miro.data?.configured || !permissions.canWrite} onClick={() => setImportOpen(true)} icon={<Download size={13} aria-hidden="true" />}>Import a MiroFish run</Button>
                  {!miro.data?.configured && <span className="tiny faint">Set MIROFISH_BASE_URL to enable</span>}
                </div>
              </div>
            </div>
          </div>
        )}
      </Card>

      <CreateSimulationModal scenario={createFor} onClose={() => setCreateFor(null)} />
      <ImportMiroModal open={importOpen} onClose={() => setImportOpen(false)} />
      <p className="tiny faint" style={{ marginTop: 14 }}>
        Simulation records are stored in this workspace with their agents, events and report. Last adapter check {miro.data ? formatDate(new Date().toISOString()) : '—'}.
      </p>
    </>
  );
}

function CreateSimulationModal({ scenario, onClose }: { scenario: Scenario | null; onClose: () => void }) {
  const navigate = useNavigate();
  const toast = useToast();
  const [name, setName] = useState('');
  const [rounds, setRounds] = useState(8);
  const [seed, setSeed] = useState(() => Math.floor(Math.random() * 900000));
  const [config, setConfig] = useState<Record<string, number | boolean>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const key = scenario?.key ?? '';

  const currentConfig = { ...(scenario?.defaultConfig ?? {}), ...config };

  const submit = async () => {
    if (!scenario) return;
    setBusy(true); setError(null);
    try {
      const result = await api.post<{ id: string; ref: string }>('/simulations', {
        scenario: scenario.key, name: name.trim() || undefined, totalRounds: rounds, seed, config: currentConfig,
      });
      toast.push('success', `Simulation ${result.ref} created`, 'Review the agents, then start the run.');
      onClose();
      navigate(`/simulations/${result.id}`);
    } catch (err) { setError(err instanceof ApiError ? err.message : 'Could not create the simulation'); }
    finally { setBusy(false); }
  };

  return (
    <Modal open={Boolean(scenario)} onClose={onClose} size="lg" title={scenario ? `Configure: ${scenario.name}` : 'New simulation'}
      subtitle="Inputs are validated on the server. The seed makes a run reproducible."
      footer={<><Button variant="ghost" onClick={onClose} type="button">Cancel</Button><Button variant="primary" onClick={submit} loading={busy} type="button">Create run</Button></>}>
      {error && <div className="error-box" role="alert">{error}</div>}
      {scenario && (
        <>
          <p className="small muted">{scenario.summary}</p>
          <div className="grid grid-2">
            <Field label="Run name" htmlFor="sim-name"><input id="sim-name" className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder={`${scenario.name} rehearsal`} /></Field>
            <Field label="Seed" htmlFor="sim-seed" hint="Same seed reproduces the same events."><input id="sim-seed" type="number" className="input" value={seed} onChange={(e) => setSeed(Number(e.target.value))} /></Field>
            <Field label="Rounds" htmlFor="sim-rounds" hint="Between 3 and 30."><input id="sim-rounds" type="number" min={3} max={30} className="input" value={rounds} onChange={(e) => setRounds(Number(e.target.value))} /></Field>
          </div>
          <div>
            <p className="label" style={{ marginBottom: 8 }}>Scenario parameters</p>
            <div className="grid grid-2" style={{ gap: 10 }}>
              {Object.entries(scenario.defaultConfig).map(([field, defaultValue]) => (
                <Field key={`${key}-${field}`} label={titleCase(field)} htmlFor={`cfg-${field}`}>
                  {typeof defaultValue === 'boolean' ? (
                    <label className="row small" style={{ gap: 8, cursor: 'pointer' }}>
                      <input type="checkbox" className="checkbox" checked={Boolean(currentConfig[field])}
                        onChange={(e) => setConfig({ ...config, [field]: e.target.checked })} />
                      {currentConfig[field] ? 'Enabled' : 'Disabled'}
                    </label>
                  ) : (
                    <input id={`cfg-${field}`} type="number" className="input" value={Number(currentConfig[field] ?? 0)}
                      onChange={(e) => setConfig({ ...config, [field]: Number(e.target.value) })} />
                  )}
                </Field>
              ))}
            </div>
          </div>
          <div>
            <p className="label" style={{ marginBottom: 6 }}>Agents in this scenario</p>
            <div className="stack" style={{ gap: 6 }}>
              {scenario.agents.map((agent) => (
                <div key={agent.name} className="row" style={{ gap: 8, alignItems: 'flex-start' }}>
                  <Badge tone={agent.role === 'attacker' || agent.role === 'insider' ? 'critical' : agent.role === 'defender' ? 'mint' : 'neutral'}>{agent.role}</Badge>
                  <div>
                    <p className="small mono">{agent.name}</p>
                    <p className="tiny faint">{agent.persona}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </Modal>
  );
}

function ImportMiroModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  const toast = useToast();
  const [remoteId, setRemoteId] = useState('');
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setBusy(true); setError(null);
    try {
      const result = await api.post<{ id: string; ref: string }>('/simulations/mirofish/import', { remoteId: remoteId.trim(), name: name.trim() || undefined });
      toast.push('success', `Imported ${result.ref}`);
      onClose(); navigate(`/simulations/${result.id}`);
    } catch (err) { setError(err instanceof ApiError ? err.message : 'Import failed'); }
    finally { setBusy(false); }
  };

  return (
    <Modal open={open} onClose={onClose} title="Import a MiroFish run" subtitle="Read only. The run was executed by the MiroFish service."
      footer={<><Button variant="ghost" onClick={onClose} type="button">Cancel</Button><Button variant="primary" onClick={submit} loading={busy} type="button">Import</Button></>}>
      {error && <div className="error-box" role="alert">{error}</div>}
      <Field label="MiroFish simulation id" htmlFor="miro-id" hint="For example sim_ab12cd34" required>
        <input id="miro-id" className="input mono" value={remoteId} onChange={(e) => setRemoteId(e.target.value)} />
      </Field>
      <Field label="Display name" htmlFor="miro-name"><input id="miro-name" className="input" value={name} onChange={(e) => setName(e.target.value)} /></Field>
      <InlineNotice tone="info">SecureFlow stores the remote status and identifier. It cannot verify MiroFish inputs or that the remote run completed.</InlineNotice>
    </Modal>
  );
}
