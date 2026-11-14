import { useState } from 'react';
import { Blocks, Plus, Play, ShieldAlert } from 'lucide-react';
import { PageHeader } from '../components/layout';
import {
  Badge, Button, Card, Drawer, EmptyState, ErrorState, Field, Modal, Pagination, StatusBadge,
  TableSkeleton, useToast, Checkbox, InlineNotice,
} from '../components/ui';
import { useApi } from '../lib/hooks';
import { api, ApiError } from '../lib/api';
import { formatDate, timeAgo, titleCase } from '../lib/format';
import { useAuth } from '../lib/auth';

type Workflow = {
  id: string; name: string; description: string; triggerType: string;
  actions: { type: string; target?: string; channel?: string; queue?: string; severity?: string }[];
  requiresApproval: boolean; enabled: boolean; executionCount?: number;
};
type Execution = {
  id: string; workflowId: string; workflowName: string; incidentId: string | null; incidentRef: string | null;
  status: string; currentStep: number; log: { step: number; action: string; status: string; detail: string; at?: string }[];
  startedBy: string | null; startedAt: string | null; finishedAt: string | null; createdAt: string;
};
type ExecPayload = { data: Execution[]; meta: { page: number; limit: number; total: number; totalPages: number } };

const ACTION_LABELS: Record<string, string> = {
  isolate_host: 'Isolate host', block_ip: 'Block IP address', disable_user: 'Disable account',
  force_password_reset: 'Force password reset', notify: 'Notify channel', open_incident: 'Open incident',
  tag_asset: 'Tag asset', open_ticket: 'Open ticket',
};
const DESTRUCTIVE = ['isolate_host', 'block_ip', 'disable_user', 'force_password_reset'];

export default function AutomationPage() {
  const { permissions } = useAuth();
  const toast = useToast();
  const [runFor, setRunFor] = useState<Workflow | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [page, setPage] = useState(1);
  const [viewing, setViewing] = useState<Execution | null>(null);

  const workflows = useApi<Workflow[]>('/automation/workflows');
  const executions = useApi<ExecPayload>(`/automation/executions?page=${page}&limit=15`);

  const toggle = async (workflow: Workflow) => {
    try {
      await api.patch(`/automation/workflows/${workflow.id}`, { enabled: !workflow.enabled });
      toast.push('success', `Workflow ${workflow.enabled ? 'disabled' : 'enabled'}`);
      workflows.refresh();
    } catch (err) { toast.push('error', 'Update failed', err instanceof ApiError ? err.message : undefined); }
  };

  const approve = async (execution: Execution) => {
    try {
      await api.post(`/automation/executions/${execution.id}/approve`);
      toast.push('success', 'Execution approved and recorded');
      executions.refresh();
      setViewing(null);
    } catch (err) { toast.push('error', 'Approval failed', err instanceof ApiError ? err.message : undefined); }
  };

  return (
    <>
      <PageHeader title="Security automation" subtitle="Response workflows with an approval gate for destructive actions. Actions are recorded as simulated unless an integration is configured."
        actions={permissions.canAdmin ? <Button variant="primary" icon={<Plus size={14} aria-hidden="true" />} onClick={() => setCreateOpen(true)}>New workflow</Button> : undefined} />

      <InlineNotice tone="warn">
        No endpoint, firewall or identity integration is configured in this deployment. Running a workflow records each step as
        <strong> simulated</strong>; it never touches a real host or account.
      </InlineNotice>

      <div className="grid grid-2" style={{ marginTop: 14 }}>
        {workflows.loading && <Card><TableSkeleton rows={4} cols={2} /></Card>}
        {workflows.error && <Card><ErrorState message={workflows.error} onRetry={workflows.refresh} /></Card>}
        {(workflows.data ?? []).map((workflow, index) => (
          <Card key={workflow.id} reveal revealDelay={index * 45} title={workflow.name} subtitle={`${titleCase(workflow.triggerType)} · ${workflow.executionCount ?? 0} executions`}
            actions={<>
              <Badge tone={workflow.enabled ? 'mint' : 'neutral'}>{workflow.enabled ? 'enabled' : 'disabled'}</Badge>
              {workflow.requiresApproval && <Badge tone="amber">approval</Badge>}
            </>}>
            <p className="small muted">{workflow.description}</p>
            <div className="stack" style={{ gap: 6, marginTop: 12 }}>
              {workflow.actions.map((action, index) => (
                <div key={`${action.type}-${index}`} className="row" style={{ gap: 8 }}>
                  <span className="badge badge-neutral">{index + 1}</span>
                  <span className="small">{ACTION_LABELS[action.type] ?? action.type}</span>
                  {DESTRUCTIVE.includes(action.type) && <Badge tone="high">destructive</Badge>}
                  <span className="tiny faint" style={{ marginLeft: 'auto' }}>{action.target ?? action.channel ?? action.queue ?? ''}</span>
                </div>
              ))}
            </div>
            <div className="row" style={{ marginTop: 14, gap: 8 }}>
              <Button size="sm" variant="primary" icon={<Play size={13} aria-hidden="true" />} onClick={() => setRunFor(workflow)} disabled={!workflow.enabled || !permissions.canWrite}>Run</Button>
              {permissions.canAdmin && <Button size="sm" variant="ghost" onClick={() => toggle(workflow)}>{workflow.enabled ? 'Disable' : 'Enable'}</Button>}
            </div>
          </Card>
        ))}
        {(workflows.data ?? []).length === 0 && !workflows.loading && (
          <Card><EmptyState title="No workflows yet" body="Create a workflow to standardise the first ten minutes of an incident." icon={<Blocks size={18} aria-hidden="true" />} /></Card>
        )}
      </div>

      <Card title="Execution history" subtitle="Every run, approval and recorded step" bodyClass="" className="" >
        {executions.loading && !executions.data ? <TableSkeleton rows={5} cols={4} /> : executions.error ? <ErrorState message={executions.error} onRetry={executions.refresh} /> : (
          <>
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>Workflow</th><th>Incident</th><th>Status</th><th>Steps</th><th>Started by</th><th className="right">When</th><th /></tr></thead>
                <tbody>
                  {executions.data?.data.map((execution) => (
                    <tr key={execution.id}>
                      <td style={{ fontWeight: 550 }}>{execution.workflowName}</td>
                      <td className="mono tiny muted">{execution.incidentRef ?? '—'}</td>
                      <td><StatusBadge status={execution.status} /></td>
                      <td className="num tiny">{execution.log.length}</td>
                      <td className="small muted">{execution.startedBy ?? '—'}</td>
                      <td className="right tiny faint">{timeAgo(execution.createdAt)}</td>
                      <td className="right">
                        <div className="row" style={{ justifyContent: 'flex-end', gap: 6 }}>
                          {execution.status === 'pending_approval' && permissions.canApprove && (
                            <Button size="sm" variant="primary" onClick={() => approve(execution)}>Approve</Button>
                          )}
                          <Button size="sm" variant="ghost" onClick={() => setViewing(execution)}>Log</Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {executions.data?.data.length === 0 && <EmptyState title="No executions yet" body="Run a workflow to see the recorded steps here." icon={<ShieldAlert size={18} aria-hidden="true" />} />}
            {executions.data && executions.data.data.length > 0 && <Pagination page={executions.data.meta.page} totalPages={executions.data.meta.totalPages} total={executions.data.meta.total} onPage={setPage} />}
          </>
        )}
      </Card>

      <RunWorkflowModal workflow={runFor} onClose={() => setRunFor(null)} onDone={() => { executions.refresh(); workflows.refresh(); }} />

      <Drawer open={Boolean(viewing)} onClose={() => setViewing(null)} title={viewing?.workflowName ?? 'Execution'} subtitle={viewing ? `${viewing.status.replace('_', ' ')} · ${formatDate(viewing.createdAt)}` : undefined}
        footer={viewing?.status === 'pending_approval' && permissions.canApprove ? (
          <Button variant="primary" size="sm" style={{ marginLeft: 'auto' }} onClick={() => approve(viewing)}>Approve and run</Button>
        ) : undefined}>
        {viewing && (
          <>
            <div className="row wrap" style={{ gap: 8 }}><StatusBadge status={viewing.status} />{viewing.incidentRef && <Badge tone="neutral">{viewing.incidentRef}</Badge>}</div>
            <div className="stack" style={{ gap: 10 }}>
              {viewing.log.map((step, index) => (
                <div key={`${step.action}-${index}`} className="row" style={{ gap: 10, alignItems: 'flex-start' }}>
                  <Badge tone={step.status === 'simulated' ? 'amber' : step.status === 'completed' ? 'mint' : 'neutral'}>{step.status}</Badge>
                  <div>
                    <p className="small strong">{ACTION_LABELS[step.action] ?? step.action}</p>
                    <p className="tiny muted">{step.detail}</p>
                  </div>
                </div>
              ))}
            </div>
            <InlineNotice tone="info">Recorded actions are audit trail entries. They are not proof that a host, account or firewall changed.</InlineNotice>
          </>
        )}
      </Drawer>

      <CreateWorkflowModal open={createOpen} onClose={() => setCreateOpen(false)} onCreated={() => workflows.refresh()} />
    </>
  );
}

function RunWorkflowModal({ workflow, onClose, onDone }: { workflow: Workflow | null; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const incidents = useApi<{ data: { id: string; ref: string; title: string }[] }>(workflow ? '/incidents?limit=100' : null);
  const [incidentId, setIncidentId] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ status: string; note: string; requiresApproval: boolean } | null>(null);

  const run = async () => {
    if (!workflow) return;
    setBusy(true); setError(null);
    try {
      const response = await api.post<{ status: string; note: string; requiresApproval: boolean }>(`/automation/workflows/${workflow.id}/run`, { incidentId: incidentId || null });
      setResult(response);
      toast.push(response.requiresApproval ? 'warn' : 'success', response.requiresApproval ? 'Waiting for approval' : 'Workflow recorded', response.note);
      onDone();
    } catch (err) { setError(err instanceof ApiError ? err.message : 'Could not run the workflow'); }
    finally { setBusy(false); }
  };

  return (
    <Modal open={Boolean(workflow)} onClose={() => { setResult(null); setIncidentId(''); onClose(); }}
      title={workflow ? `Run: ${workflow.name}` : 'Run workflow'}
      subtitle={workflow?.requiresApproval ? 'This workflow contains destructive actions and needs approval.' : 'Actions will be recorded immediately.'}
      footer={<><Button variant="ghost" onClick={() => { setResult(null); setIncidentId(''); onClose(); }} type="button">Close</Button><Button variant="primary" onClick={run} loading={busy} type="button">Run workflow</Button></>}>
      {error && <div className="error-box" role="alert">{error}</div>}
      {result && <InlineNotice tone={result.requiresApproval ? 'warn' : 'success'}>{result.note}</InlineNotice>}
      <Field label="Link to incident" htmlFor="wf-inc">
        <select id="wf-inc" className="select" value={incidentId} onChange={(e) => setIncidentId(e.target.value)}>
          <option value="">No incident</option>
          {(incidents.data?.data ?? []).map((incident) => <option key={incident.id} value={incident.id}>{incident.ref} · {incident.title}</option>)}
        </select>
      </Field>
      <p className="tiny faint">Each step is written to the execution log with its outcome. No external system is contacted.</p>
    </Modal>
  );
}

function CreateWorkflowModal({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: () => void }) {
  const toast = useToast();
  const [form, setForm] = useState({ name: '', description: '', triggerType: 'detection.critical', requiresApproval: true });
  const [selected, setSelected] = useState<string[]>(['notify']);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const toggleAction = (action: string) => setSelected((current) => current.includes(action) ? current.filter((a) => a !== action) : [...current, action]);

  const submit = async () => {
    setError(null);
    if (form.name.trim().length < 4) { setError('Name the workflow'); return; }
    if (selected.length === 0) { setError('Choose at least one action'); return; }
    setBusy(true);
    try {
      await api.post('/automation/workflows', {
        name: form.name.trim(), description: form.description.trim(), triggerType: form.triggerType,
        actions: selected.map((type) => ({ type })), requiresApproval: form.requiresApproval,
      });
      toast.push('success', 'Workflow created');
      onCreated(); onClose();
      setForm({ name: '', description: '', triggerType: 'detection.critical', requiresApproval: true });
      setSelected(['notify']);
    } catch (err) { setError(err instanceof ApiError ? err.message : 'Could not create the workflow'); }
    finally { setBusy(false); }
  };

  return (
    <Modal open={open} onClose={onClose} title="New response workflow" subtitle="Workflows are declarative. The engine records each action; it does not call external systems."
      footer={<><Button variant="ghost" onClick={onClose} type="button">Cancel</Button><Button variant="primary" onClick={submit} loading={busy} type="button">Create workflow</Button></>}>
      {error && <div className="error-box" role="alert">{error}</div>}
      <Field label="Name" htmlFor="w-name" required><input id="w-name" className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Contain a confirmed phishing submission" /></Field>
      <Field label="Description" htmlFor="w-desc"><textarea id="w-desc" className="textarea" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
      <Field label="Trigger" htmlFor="w-trigger"><input id="w-trigger" className="input mono" value={form.triggerType} onChange={(e) => setForm({ ...form, triggerType: e.target.value })} placeholder="detection.credential_stuffing" /></Field>
      <div>
        <p className="label" style={{ marginBottom: 8 }}>Actions</p>
        <div className="grid grid-2" style={{ gap: 8 }}>
          {Object.entries(ACTION_LABELS).map(([key, label]) => (
            <Checkbox key={key} checked={selected.includes(key)} onChange={() => toggleAction(key)} label={label} />
          ))}
        </div>
      </div>
      <Checkbox checked={form.requiresApproval} onChange={(v) => setForm({ ...form, requiresApproval: v })} label="Require approval before destructive actions run" />
    </Modal>
  );
}
