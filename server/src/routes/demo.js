import { Router } from 'express';
import { z } from 'zod';
import { asyncHandler, badRequest, created, ok, validate } from '../lib/http.js';
import { requireAuth, requireRole } from '../lib/auth.js';
import { audit } from '../lib/audit.js';
import { getDemoStatus, generateDemoData, resetDemoData } from '../services/demo.js';
import { SCENARIOS, createSimulation, startSimulation } from '../services/simulation.js';

const router = Router();
router.use(requireAuth);

const DEMO_SCENARIOS = ['brute-force', 'phishing', 'malware', 'sql-injection', 'suspicious-admin'];

router.get('/status', asyncHandler(async (req, res) => {
  return ok(res, getDemoStatus(req.user.orgId));
}));

router.get('/runs', requireRole('admin'), asyncHandler(async (req, res) => {
  return ok(res, getDemoStatus(req.user.orgId).runs);
}));

router.post('/generate', requireRole('admin'), asyncHandler(async (req, res) => {
  const result = generateDemoData({ orgId: req.user.orgId, userId: req.user.id });
  audit(req, 'demo.generated', 'workspace', req.user.orgId, { batchId: result.batchId, counts: result.counts });
  return created(res, result);
}));

router.post('/reset', requireRole('admin'), asyncHandler(async (req, res) => {
  validate(z.object({ confirm: z.literal('RESET', { errorMap: () => ({ message: 'Type RESET to confirm' }) }) }), req.body);
  const result = resetDemoData({ orgId: req.user.orgId, userId: req.user.id });
  audit(req, 'demo.reset', 'workspace', req.user.orgId, result.deleted);
  return ok(res, result);
}));

router.post('/scenarios/run-all', requireRole('admin'), asyncHandler(async (req, res) => {
  const runs = [];
  for (const key of DEMO_SCENARIOS) {
    const scenario = SCENARIOS.find((entry) => entry.key === key);
    if (!scenario) continue;
    const sim = createSimulation(req.user.orgId, req.user.id, {
      scenario: key, name: `Demo scenario: ${scenario.name}`, seed: 424242,
    });
    startSimulation(req.user.orgId, sim.id);
    runs.push({ id: sim.id, ref: sim.ref, scenario: key });
  }
  audit(req, 'demo.scenarios_started', 'workspace', req.user.orgId, { scenarios: runs.map((run) => run.scenario) });
  return created(res, { runs });
}));

router.post('/scenarios/:key/run', requireRole('admin'), asyncHandler(async (req, res) => {
  const scenario = SCENARIOS.find((entry) => entry.key === req.params.key);
  if (!scenario) throw badRequest('Unknown simulation scenario');
  const sim = createSimulation(req.user.orgId, req.user.id, {
    scenario: scenario.key, name: `Demo scenario: ${scenario.name}`, seed: 424242,
  });
  startSimulation(req.user.orgId, sim.id);
  audit(req, 'demo.scenario_started', 'simulation', sim.id, { scenario: scenario.key });
  return created(res, { id: sim.id, ref: sim.ref, scenario: scenario.key });
}));

export default router;
