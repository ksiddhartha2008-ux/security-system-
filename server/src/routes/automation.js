import { Router } from 'express';
import { z } from 'zod';
import { all, get, run, newId, nowIso, parseJson } from '../db.js';
import { asyncHandler, badRequest, created, notFound, ok, pageParams, paginated, validate } from '../lib/http.js';
import { requireAuth, requireRole } from '../lib/auth.js';
import { audit } from '../lib/audit.js';

const router = Router();
router.use(requireAuth);

const ACTION_TYPES = ['isolate_host', 'block_ip', 'disable_user', 'force_password_reset', 'notify', 'open_incident', 'tag_asset', 'open_ticket'];
const DESTRUCTIVE = new Set(['isolate_host', 'block_ip', 'disable_user', 'force_password_reset']);

const mapWorkflow = (w) => ({
  id: w.id, name: w.name, description: w.description, triggerType: w.trigger_type,
  actions: parseJson(w.actions, []), requiresApproval: w.requires_approval === 1, enabled: w.enabled === 1,
  executionCount: w.execution_count ?? undefined, createdAt: w.created_at,
});

router.get('/workflows', asyncHandler(async (req, res) => {
  const rows = all(
    `SELECT w.*, (SELECT COUNT(*) FROM workflow_executions e WHERE e.workflow_id = w.id) AS execution_count
       FROM response_workflows w WHERE w.org_id = ? ORDER BY w.created_at`, req.user.orgId,
  );
  return ok(res, rows.map(mapWorkflow));
}));

router.post('/workflows', requireRole('admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({
    name: z.string().trim().min(4).max(160),
    description: z.string().trim().max(1000).default(''),
    triggerType: z.string().trim().min(3).max(80),
    actions: z.array(z.object({
      type: z.enum(ACTION_TYPES),
      target: z.string().trim().max(120).optional(),
      channel: z.string().trim().max(80).optional(),
      severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
      queue: z.string().trim().max(80).optional(),
    })).min(1).max(8),
    requiresApproval: z.boolean().default(true),
    enabled: z.boolean().default(true),
  }), req.body);
  const id = newId('wf');
  run(
    `INSERT INTO response_workflows (id, org_id, name, description, trigger_type, trigger_config, actions, requires_approval, enabled, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, '{}', ?, ?, ?, ?, ?)`,
    id, req.user.orgId, body.name, body.description, body.triggerType, JSON.stringify(body.actions),
    body.requiresApproval ? 1 : 0, body.enabled ? 1 : 0, nowIso(), nowIso(),
  );
  audit(req, 'workflow.created', 'response_workflow', id, { name: body.name, actions: body.actions.length });
  return created(res, mapWorkflow(get('SELECT * FROM response_workflows WHERE id = ?', id)));
}));

router.patch('/workflows/:id', requireRole('admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({
    enabled: z.boolean().optional(),
    requiresApproval: z.boolean().optional(),
    description: z.string().trim().max(1000).optional(),
  }), req.body);
  const row = get('SELECT * FROM response_workflows WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!row) throw notFound('Workflow not found');
  const fields = [];
  const params = [];
  if (body.enabled !== undefined) { fields.push('enabled = ?'); params.push(body.enabled ? 1 : 0); }
  if (body.requiresApproval !== undefined) { fields.push('requires_approval = ?'); params.push(body.requiresApproval ? 1 : 0); }
  if (body.description !== undefined) { fields.push('description = ?'); params.push(body.description); }
  if (!fields.length) throw badRequest('Nothing to update');
  fields.push('updated_at = ?'); params.push(nowIso());
  run(`UPDATE response_workflows SET ${fields.join(', ')} WHERE id = ? AND org_id = ?`, ...params, row.id, req.user.orgId);
  audit(req, 'workflow.updated', 'response_workflow', row.id, { fields: Object.keys(body) });
  return ok(res, mapWorkflow(get('SELECT * FROM response_workflows WHERE id = ?', row.id)));
}));

function execute(executionId) {
  const execution = get('SELECT * FROM workflow_executions WHERE id = ?', executionId);
  const workflow = get('SELECT * FROM response_workflows WHERE id = ?', execution.workflow_id);
  const actions = parseJson(workflow.actions, []);
  const log = parseJson(execution.log, []);
  const ts = nowIso();
  const updated = [];
  for (let i = 0; i < actions.length; i += 1) {
    const action = actions[i];
    const step = i + 1;
    // No endpoint or firewall integration is configured in this deployment, so the
    // action is recorded as simulated instead of pretending it happened.
    updated.push({
      step, action: action.type, status: 'simulated',
      detail: `${action.type} recorded for target ${action.target ?? action.channel ?? action.queue ?? 'incident context'}. No external integration is configured, so no production system was changed.`,
      at: ts,
    });
  }
  run(
    `UPDATE workflow_executions SET status = 'completed', current_step = ?, log = ?, finished_at = ?, error = NULL WHERE id = ?`,
    actions.length, JSON.stringify([...log.filter((l) => l.status !== 'awaiting_approval'), ...updated]), ts, executionId,
  );
  return get('SELECT * FROM workflow_executions WHERE id = ?', executionId);
}

router.post('/workflows/:id/run', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({
    incidentId: z.string().trim().max(64).optional().nullable(),
    note: z.string().trim().max(500).optional(),
  }), req.body);
  const workflow = get('SELECT * FROM response_workflows WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!workflow) throw notFound('Workflow not found');
  if (workflow.enabled !== 1) throw badRequest('This workflow is disabled');
  if (body.incidentId && !get('SELECT id FROM incidents WHERE id = ? AND org_id = ?', body.incidentId, req.user.orgId)) {
    throw notFound('Incident not found in this workspace');
  }
  const actions = parseJson(workflow.actions, []);
  const needsApproval = workflow.requires_approval === 1 && actions.some((a) => DESTRUCTIVE.has(a.type));
  const id = newId('wfx');
  const ts = nowIso();
  const initialLog = needsApproval
    ? [{ step: 1, action: actions[0]?.type ?? 'unknown', status: 'awaiting_approval', detail: 'Workflow requires human approval before running destructive actions.', at: ts }]
    : [];
  run(
    `INSERT INTO workflow_executions (id, org_id, workflow_id, incident_id, status, current_step, log, started_by, started_at, created_at)
     VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?)`,
    id, req.user.orgId, workflow.id, body.incidentId ?? null,
    needsApproval ? 'pending_approval' : 'running', JSON.stringify(initialLog), req.user.id, ts, ts,
  );
  const execution = needsApproval ? get('SELECT * FROM workflow_executions WHERE id = ?', id) : execute(id);
  audit(req, 'workflow.executed', 'workflow_execution', id, { workflowId: workflow.id, needsApproval });
  return created(res, {
    id,
    status: execution.status,
    requiresApproval: needsApproval,
    log: parseJson(execution.log, []),
    note: needsApproval
      ? 'Waiting for an analyst or admin to approve before any action is recorded as run.'
      : 'Actions were recorded as simulated. No production system was contacted.',
  });
}));

router.post('/executions/:id/approve', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const execution = get('SELECT * FROM workflow_executions WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!execution) throw notFound('Execution not found');
  if (execution.status !== 'pending_approval') throw badRequest('This execution is not waiting for approval');
  run('UPDATE workflow_executions SET approved_by = ? WHERE id = ?', req.user.id, execution.id);
  const done = execute(execution.id);
  audit(req, 'workflow.approved', 'workflow_execution', execution.id, {});
  return ok(res, { id: done.id, status: done.status, log: parseJson(done.log, []) });
}));

router.post('/executions/:id/cancel', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const execution = get('SELECT * FROM workflow_executions WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!execution) throw notFound('Execution not found');
  if (!['pending_approval', 'running'].includes(execution.status)) throw badRequest('Only pending executions can be cancelled');
  run(`UPDATE workflow_executions SET status = 'cancelled', finished_at = ? WHERE id = ?`, nowIso(), execution.id);
  audit(req, 'workflow.cancelled', 'workflow_execution', execution.id, {});
  return ok(res, { id: execution.id, status: 'cancelled' });
}));

router.get('/executions', asyncHandler(async (req, res) => {
  const { limit, page, offset } = pageParams(req, { maxLimit: 100, defaultLimit: 25 });
  const where = ['e.org_id = ?'];
  const params = [req.user.orgId];
  if (req.query.status) { where.push('e.status = ?'); params.push(String(req.query.status)); }
  const sqlWhere = where.join(' AND ');
  const total = get(`SELECT COUNT(*) c FROM workflow_executions e WHERE ${sqlWhere}`, ...params).c;
  const rows = all(
    `SELECT e.*, w.name AS workflow_name, i.ref AS incident_ref, u.name AS started_by_name
       FROM workflow_executions e
       LEFT JOIN response_workflows w ON w.id = e.workflow_id
       LEFT JOIN incidents i ON i.id = e.incident_id
       LEFT JOIN users u ON u.id = e.started_by
      WHERE ${sqlWhere} ORDER BY e.created_at DESC LIMIT ? OFFSET ?`,
    ...params, limit, offset,
  );
  return paginated(res, rows.map((e) => ({
    id: e.id, workflowId: e.workflow_id, workflowName: e.workflow_name, incidentId: e.incident_id,
    incidentRef: e.incident_ref, status: e.status, currentStep: e.current_step, log: parseJson(e.log, []),
    startedBy: e.started_by_name, startedAt: e.started_at, finishedAt: e.finished_at, error: e.error, createdAt: e.created_at,
  })), total, { page, limit });
}));

export default router;
