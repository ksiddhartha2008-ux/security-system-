import { Router } from 'express';
import { z } from 'zod';
import { all, get, run, nowIso, parseJson } from '../db.js';
import { asyncHandler, badRequest, created, notFound, ok, pageParams, paginated, validate } from '../lib/http.js';
import { requireAuth, requireRole } from '../lib/auth.js';
import { audit } from '../lib/audit.js';
import { rateLimit } from '../lib/ratelimit.js';
import {
  SCENARIOS, createSimulation, startSimulation, cancelSimulation, getSimulationDetail, DISCLAIMER,
} from '../services/simulation.js';
import { mirofishStatus, importMirofishRun } from '../services/mirofish.js';

const router = Router();
router.use(requireAuth);

router.get('/scenarios', asyncHandler(async (_req, res) => ok(res, SCENARIOS.map((s) => ({
  key: s.key, name: s.name, summary: s.summary, category: s.category, defaultRounds: s.defaultRounds,
  defaultConfig: s.defaultConfig, agents: s.agents,
})))));

router.get('/mirofish/status', asyncHandler(async (_req, res) => ok(res, await mirofishStatus())));

router.get('/', asyncHandler(async (req, res) => {
  const { limit, page, offset } = pageParams(req, { maxLimit: 100, defaultLimit: 20 });
  const where = ['s.org_id = ?'];
  const params = [req.user.orgId];
  if (req.query.status) { where.push('s.status = ?'); params.push(String(req.query.status)); }
  if (req.query.scenario) { where.push('s.scenario = ?'); params.push(String(req.query.scenario)); }
  const sqlWhere = where.join(' AND ');
  const total = get(`SELECT COUNT(*) c FROM simulations s WHERE ${sqlWhere}`, ...params).c;
  const rows = all(
    `SELECT s.*, u.name AS created_by_name FROM simulations s LEFT JOIN users u ON u.id = s.created_by
      WHERE ${sqlWhere} ORDER BY s.created_at DESC LIMIT ? OFFSET ?`, ...params, limit, offset,
  );
  return paginated(res, rows.map((s) => ({
    id: s.id, ref: s.ref, name: s.name, scenario: s.scenario, status: s.status, engine: s.engine,
    progress: s.progress, currentRound: s.current_round, totalRounds: s.total_rounds, riskScore: s.risk_score,
    summary: parseJson(s.summary, {}), error: s.error, synthetic: true,
    createdBy: s.created_by_name, createdAt: s.created_at, finishedAt: s.finished_at,
  })), total, { page, limit });
}));

router.post('/', requireRole('analyst', 'admin'), rateLimit({ windowMs: 3600_000, max: 60, keyPrefix: 'sim-create' }), asyncHandler(async (req, res) => {
  const body = validate(z.object({
    scenario: z.string().trim().min(3).max(40),
    name: z.string().trim().max(120).optional(),
    totalRounds: z.number().int().min(3).max(30).optional(),
    seed: z.number().int().min(0).max(1_000_000).optional(),
    config: z.record(z.string(), z.union([z.number(), z.boolean(), z.string()])).optional(),
  }), req.body);
  const sim = createSimulation(req.user.orgId, req.user.id, body);
  audit(req, 'simulation.created', 'simulation', sim.id, { scenario: sim.scenario, totalRounds: sim.totalRounds });
  return created(res, { id: sim.id, ref: sim.ref, scenario: sim.scenario, agents: sim.agents.length, totalRounds: sim.totalRounds, status: 'draft' });
}));

router.get('/:id', asyncHandler(async (req, res) => ok(res, getSimulationDetail(req.user.orgId, req.params.id))));

router.post('/:id/start', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const result = startSimulation(req.user.orgId, req.params.id);
  audit(req, 'simulation.started', 'simulation', req.params.id, {});
  return ok(res, result);
}));

router.post('/:id/cancel', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const result = cancelSimulation(req.user.orgId, req.params.id);
  audit(req, 'simulation.cancelled', 'simulation', req.params.id, {});
  return ok(res, result);
}));

router.delete('/:id', requireRole('admin'), asyncHandler(async (req, res) => {
  const sim = get('SELECT * FROM simulations WHERE id = ? AND org_id = ?', req.params.id, req.user.orgId);
  if (!sim) throw notFound('Simulation not found');
  if (sim.status === 'running') throw badRequest('Cancel the run before deleting it');
  run('DELETE FROM simulations WHERE id = ? AND org_id = ?', sim.id, req.user.orgId);
  audit(req, 'simulation.deleted', 'simulation', sim.id, { ref: sim.ref });
  return ok(res, { id: sim.id, deleted: true });
}));

router.get('/:id/report', asyncHandler(async (req, res) => {
  const detail = getSimulationDetail(req.user.orgId, req.params.id);
  if (!detail.report) throw notFound('This simulation has no report yet');
  return ok(res, detail.report);
}));

router.get('/:id/report/download', asyncHandler(async (req, res) => {
  const detail = getSimulationDetail(req.user.orgId, req.params.id);
  if (!detail.report) throw notFound('This simulation has no report yet');
  const lines = [
    `# ${detail.name}`,
    '',
    `Reference: ${detail.ref}  `,
    `Scenario: ${detail.scenarioName}  `,
    `Engine: ${detail.engine}  `,
    `Rounds: ${detail.totalRounds}  `,
    `Risk score: ${detail.report.riskScore}/100  `,
    `Generated: ${detail.report.createdAt}`,
    '',
    '## Narrative',
    '',
    detail.report.narrative,
    '',
    '## Findings',
    '',
    ...detail.report.findings.map((f) => `- ${f}`),
    '',
    '## Recommendations',
    '',
    ...detail.report.recommendations.map((r) => `- ${r}`),
    '',
    '## Agents',
    '',
    '| Agent | Role | Actions | Risk |',
    '| --- | --- | --- | --- |',
    ...detail.agents.map((a) => `| ${a.name} | ${a.role} | ${a.activityCount} | ${a.riskScore} |`),
    '',
    `> ${DISCLAIMER}`,
  ];
  res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${detail.ref}-report.md"`);
  return res.send(lines.join('\n'));
}));

router.post('/mirofish/import', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({
    remoteId: z.string().trim().min(3).max(64),
    name: z.string().trim().max(120).optional(),
  }), req.body);
  const result = await importMirofishRun({
    orgId: req.user.orgId, userId: req.user.id, remoteId: body.remoteId, name: body.name,
  });
  audit(req, 'simulation.mirofish_imported', 'simulation', result.id, { remoteId: body.remoteId });
  return created(res, result);
}));

export default router;
