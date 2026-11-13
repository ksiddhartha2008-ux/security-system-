import express from 'express';
import { existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { migrate, db, get, nowIso } from './db.js';
import { attachUser, checkOrigin, requireAuth, requireCsrf, SESSION_COOKIE } from './lib/auth.js';
import { errorHandler, notFoundHandler } from './lib/http.js';
import { rateLimit, setRateLimitStore } from './lib/ratelimit.js';
import { createRateLimitStore } from './lib/ratelimitStore.js';
import { bus } from './lib/events.js';
import { seed } from './seed.js';
import { isDemoMode } from './lib/demo.js';
import { createBootstrapAdmin } from './lib/bootstrap.js';
import { checkProductionConfig } from './lib/config.js';
import { websiteProtectionEnabled } from './lib/websiteFlag.js';
import { startWebsiteScheduler } from './services/websiteScheduler.js';
import { recoverInterruptedSimulations, SCENARIOS, DISCLAIMER } from './services/simulation.js';

import authRoutes from './routes/auth.js';
import overviewRoutes from './routes/overview.js';
import eventRoutes from './routes/events.js';
import assetRoutes from './routes/assets.js';
import incidentRoutes from './routes/incidents.js';
import investigationRoutes from './routes/investigations.js';
import intelRoutes from './routes/intel.js';
import detectionRoutes from './routes/detections.js';
import phishingRoutes from './routes/phishing.js';
import vulnerabilityRoutes from './routes/vulnerabilities.js';
import automationRoutes from './routes/automation.js';
import forensicRoutes from './routes/forensics.js';
import networkRoutes from './routes/network.js';
import reportRoutes from './routes/reports.js';
import simulationRoutes from './routes/simulations.js';
import demoRoutes from './routes/demo.js';
import settingsRoutes from './routes/settings.js';
import websiteRoutes from './routes/websites.js';
import ingestRoutes from './routes/ingest.js';

const here = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT ?? 4000);

migrate();
const configCheck = checkProductionConfig();
for (const warning of configCheck.warnings) console.warn(`[config] ${warning}`);
if (configCheck.errors.length) {
  for (const error of configCheck.errors) console.error(`[config] ${error}`);
  console.error('[startup] Refusing to start with an insecure production configuration.');
  process.exit(1);
}
const demoMode = isDemoMode();
const firstRun = !get('SELECT id FROM organizations LIMIT 1');
if (firstRun) {
  if (demoMode) {
    console.log('[startup] empty database detected, seeding the demo workspace');
    seed();
  } else {
    const email = process.env.SF_BOOTSTRAP_EMAIL;
    const password = process.env.SF_BOOTSTRAP_PASSWORD;
    if (!email || !password) {
      console.error('[startup] No workspace exists and demo mode is disabled.');
      console.error('[startup] Set SF_BOOTSTRAP_EMAIL and SF_BOOTSTRAP_PASSWORD (12 or more characters), then restart.');
      console.error('[startup] Or set SF_DEMO_MODE=true for a throwaway demo deployment with synthetic data.');
      process.exit(1);
    }
    try {
      await createBootstrapAdmin({
        email,
        password,
        name: process.env.SF_BOOTSTRAP_NAME || 'Workspace owner',
        organizationName: process.env.SF_BOOTSTRAP_ORG || 'SecureFlow Workspace',
      });
    } catch (err) {
      console.error(`[startup] bootstrap failed: ${err.message}`);
      process.exit(1);
    }
  }
}
const recovered = recoverInterruptedSimulations();
if (recovered) console.log(`[startup] marked ${recovered} interrupted simulation(s) as failed`);

if (process.env.SF_TRUST_PROXY === 'true') app.set('trust proxy', 1);
app.disable('x-powered-by');

const rateLimitStore = createRateLimitStore();
setRateLimitStore(rateLimitStore);
console.log(`[secureflow] rate limit store: ${rateLimitStore.kind}${process.env.SF_REDIS_URL ? '' : ' (single process)'}`);

app.use((req, res, next) => {
  req.requestId = crypto.randomUUID();
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  res.setHeader('X-Request-Id', req.requestId);
  next();
});

// Ingestion is mounted before cookie parsing and CSRF: it authenticates with the
// API key only, ignores ambient credentials and caps the body while reading.
app.use('/api/v1/ingest', ingestRoutes);

app.use(express.json({ limit: '8mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));
app.use(attachUser);
app.use(checkOrigin);
app.use(requireCsrf);
app.use('/api', rateLimit({ windowMs: 60_000, max: 1200, keyPrefix: 'api' }));
app.use('/api', (_req, res, next) => {
  // Tenant data and session state must not sit in a shared or browser cache.
  res.setHeader('Cache-Control', 'no-store');
  next();
});

/** Lightweight liveness probe. Contains no tenant data. */
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', service: 'secureflow-api', time: nowIso(), version: '1.0.0' });
});

/** Readiness probe: the API can serve requests only if its database answers. */
app.get('/api/health/ready', (req, res) => {
  try {
    get('SELECT 1 AS ok');
    return res.json({
      status: 'ok',
      checks: { database: 'ok', rateLimitStore: rateLimitStore.kind },
      time: nowIso(),
    });
  } catch (err) {
    return res.status(503).json({ status: 'degraded', checks: { database: 'error' }, time: nowIso() });
  }
});

app.use('/api/auth', authRoutes);
app.use('/api/overview', overviewRoutes);
app.use('/api/events', eventRoutes);
app.use('/api/assets', assetRoutes);
app.use('/api/incidents', incidentRoutes);
app.use('/api/investigations', investigationRoutes);
app.use('/api/threat-intel', intelRoutes);
app.use('/api/detections', detectionRoutes);
app.use('/api/phishing', phishingRoutes);
app.use('/api/vulnerabilities', vulnerabilityRoutes);
app.use('/api/automation', automationRoutes);
app.use('/api/forensics', forensicRoutes);
app.use('/api/network', networkRoutes);
app.use('/api/reports', reportRoutes);
app.use('/api/simulations', simulationRoutes);
app.use('/api/demo', demoRoutes);
app.use('/api/settings', settingsRoutes);
app.use('/api/v1/websites', websiteRoutes);

/** Server sent events for live monitoring and simulation progress. */
app.get('/api/stream', requireAuth, (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  const send = (event, payload) => {
    res.write(`event: ${event}\n`);
    res.write(`data: ${JSON.stringify(payload)}\n\n`);
  };
  send('connected', { at: nowIso(), orgId: req.user.orgId });
  const listener = (message) => {
    if (message.orgId !== req.user.orgId) return;
    send(message.event, message.payload);
  };
  bus.on('org', listener);
  const heartbeat = setInterval(() => res.write(': keep-alive\n\n'), 25_000);
  req.on('close', () => {
    clearInterval(heartbeat);
    bus.off('org', listener);
  });
});

/** Small self describing API index so the docs page has a live source of truth. */
app.get('/api/docs', requireAuth, (req, res) => {
  res.json({
    name: 'SecureFlow AI API',
    version: '1.0.0',
    baseUrl: '/api',
    authentication: { scheme: 'session cookie', cookie: SESSION_COOKIE, note: 'HttpOnly, SameSite=Lax, 7 day expiry' },
    errorEnvelope: { error: { code: 'string', message: 'string', details: 'optional array' } },
    pagination: { query: ['page', 'limit'], envelope: { data: 'array', meta: { page: 'number', limit: 'number', total: 'number', totalPages: 'number' } } },
    groups: [
      { tag: 'Auth', endpoints: [
        ['POST', '/api/auth/register', 'Create an organization and its first admin'],
        ['POST', '/api/auth/login', 'Start a session'],
        ['POST', '/api/auth/logout', 'Destroy the current session'],
        ['GET', '/api/auth/me', 'Current user, organization and permissions'],
        ['PATCH', '/api/auth/me', 'Update profile or password'],
      ] },
      { tag: 'Overview', endpoints: [
        ['GET', '/api/overview/summary', 'Database backed KPIs for the dashboard'],
        ['GET', '/api/overview/trends?days=14', 'Daily event, incident, detection and network trends'],
      ] },
      { tag: 'Monitoring', endpoints: [
        ['GET', '/api/events', 'Paginated events with filters'],
        ['POST', '/api/events', 'Ingest a normalised event and run detection rules'],
        ['GET', '/api/events/:id', 'Event detail with related telemetry'],
        ['PATCH', '/api/events/:id', 'Triage status'],
        ['GET', '/api/stream', 'Server sent events'],
      ] },
      { tag: 'Assets', endpoints: [
        ['GET', '/api/assets', 'Asset inventory'], ['POST', '/api/assets', 'Register an asset'],
        ['GET', '/api/assets/:id', 'Asset detail with events, detections, vulnerabilities'],
        ['PATCH', '/api/assets/:id', 'Update an asset'], ['DELETE', '/api/assets/:id', 'Delete (admin)'],
      ] },
      { tag: 'Incidents', endpoints: [
        ['GET', '/api/incidents', 'Incident queue'], ['POST', '/api/incidents', 'Open an incident'],
        ['GET', '/api/incidents/:id', 'Timeline and linked detections'],
        ['PATCH', '/api/incidents/:id', 'Status transition, assignment, severity'],
        ['POST', '/api/incidents/:id/notes', 'Add a timeline note'],
      ] },
      { tag: 'Investigations', endpoints: [
        ['GET', '/api/investigations', 'List investigations'], ['POST', '/api/investigations', 'Open one'],
        ['GET', '/api/investigations/:id', 'Correlated timeline, indicators, assets'],
        ['PATCH', '/api/investigations/:id', 'Status and findings'],
        ['POST', '/api/investigations/:id/notes', 'Analyst note'],
      ] },
      { tag: 'Threat intelligence', endpoints: [
        ['GET', '/api/threat-intel', 'Indicator inventory'], ['POST', '/api/threat-intel', 'Add an indicator'],
        ['POST', '/api/threat-intel/lookup', 'Lookup local and external reputation'],
        ['GET', '/api/threat-intel/lookups/recent', 'Recent lookups'],
      ] },
      { tag: 'Detections', endpoints: [
        ['GET', '/api/detections', 'Detection queue'], ['GET', '/api/detections/:id', 'Explainable detail'],
        ['GET', '/api/detections/rules', 'Rule catalogue'], ['PATCH', '/api/detections/rules/:id', 'Enable or tune a rule (admin)'],
        ['POST', '/api/detections/run', 'Evaluate rules now'],
        ['POST', '/api/detections/:id/feedback', 'Confirm or dismiss'],
        ['POST', '/api/detections/:id/promote', 'Create an incident'],
      ] },
      { tag: 'Phishing scanner', endpoints: [
        ['POST', '/api/phishing/scan', 'SSRF protected URL analysis'],
        ['GET', '/api/phishing', 'Scan history'],
      ] },
      { tag: 'Vulnerabilities', endpoints: [
        ['GET', '/api/vulnerabilities', 'Vulnerability register'], ['POST', '/api/vulnerabilities', 'Record a finding'],
        ['PATCH', '/api/vulnerabilities/:id', 'Remediation status'],
      ] },
      { tag: 'Automation', endpoints: [
        ['GET', '/api/automation/workflows', 'Response workflows'], ['POST', '/api/automation/workflows', 'Create (admin)'],
        ['POST', '/api/automation/workflows/:id/run', 'Run with approval gate'],
        ['POST', '/api/automation/executions/:id/approve', 'Approve a pending run'],
        ['GET', '/api/automation/executions', 'Execution history'],
      ] },
      { tag: 'Forensics', endpoints: [
        ['GET', '/api/forensics', 'Evidence register'], ['POST', '/api/forensics', 'Seal new evidence and hash it'],
        ['GET', '/api/forensics/:id', 'Metadata and chain of custody'],
        ['GET', '/api/forensics/:id/download', 'Download with hash header'],
        ['POST', '/api/forensics/:id/verify', 'Recompute SHA-256'],
        ['POST', '/api/forensics/:id/custody', 'Custody action'],
      ] },
      { tag: 'Network', endpoints: [
        ['GET', '/api/network', 'Flow records'], ['GET', '/api/network/summary', 'Traffic summary'],
        ['POST', '/api/network', 'Ingest a flow record'],
      ] },
      { tag: 'Reports', endpoints: [
        ['GET', '/api/reports/types', 'Available report types'], ['POST', '/api/reports/generate', 'Generate from stored data'],
        ['GET', '/api/reports/:id', 'Report detail'], ['GET', '/api/reports/:id/download?format=md|csv|json', 'Export'],
      ] },
      { tag: 'Threat simulation lab', endpoints: [
        ['GET', '/api/simulations/scenarios', 'Five scenario definitions'],
        ['GET', '/api/simulations', 'Run history'], ['POST', '/api/simulations', 'Create a run'],
        ['POST', '/api/simulations/:id/start', 'Start the agent run'], ['POST', '/api/simulations/:id/cancel', 'Cancel'],
        ['GET', '/api/simulations/:id', 'Agents, events, report'],
        ['GET', '/api/simulations/:id/report/download', 'Markdown report'],
        ['GET', '/api/simulations/mirofish/status', 'MiroFish adapter status'],
        ['POST', '/api/simulations/mirofish/import', 'Import a MiroFish run'],
      ] },
      { tag: 'Website protection', endpoints: [
        ['POST', '/api/v1/websites', 'Register a website and create a DNS challenge (admin)'],
        ['GET', '/api/v1/websites', 'Websites with verification and connection status'],
        ['GET', '/api/v1/websites/:id', 'Detail, verification record, keys and counters'],
        ['POST', '/api/v1/websites/:id/verify', 'Run one DNS TXT check'],
        ['POST', '/api/v1/websites/:id/verification/restart', 'Replace an expired challenge'],
        ['PATCH', '/api/v1/websites/:id', 'Name, criticality and sensitive paths (admin)'],
        ['DELETE', '/api/v1/websites/:id', 'Soft delete and revoke keys (admin, recent auth)'],
        ['POST', '/api/v1/websites/:id/keys', 'Create an API key once (admin, recent auth)'],
        ['GET', '/api/v1/websites/:id/keys', 'Key metadata, never secrets (admin)'],
        ['DELETE', '/api/v1/websites/:id/keys/:keyId', 'Revoke immediately (admin, recent auth)'],
        ['GET', '/api/v1/websites/:id/events', 'Website events'],
        ['GET', '/api/v1/websites/:id/detections', 'Website detections'],
        ['GET', '/api/v1/websites/:id/incidents', 'Linked incidents'],
        ['GET', '/api/v1/websites/:id/export', 'Tenant scoped export (admin)'],
        ['POST', '/api/v1/websites/:id/data-deletion', 'Delete website event data (admin, recent auth)'],
        ['POST', '/api/v1/ingest/website-events', 'SDK ingestion, API key only'],
      ] },
      { tag: 'Settings', endpoints: [
        ['GET', '/api/settings/organization', 'Organization settings'], ['PATCH', '/api/settings/organization', 'Update (admin)'],
        ['GET', '/api/settings/users', 'Members'], ['POST', '/api/settings/users', 'Create a member (admin)'],
        ['GET', '/api/settings/integrations', 'Integration status'], ['POST', '/api/settings/integrations/:key/test', 'Test configuration'],
        ['GET', '/api/settings/audit-logs', 'Audit trail (admin)'], ['GET', '/api/settings/health', 'System health'],
      ] },
    ],
    scenarios: SCENARIOS.map((s) => ({ key: s.key, name: s.name, rounds: s.defaultRounds })),
    features: { websiteProtection: websiteProtectionEnabled() },
    simulationDisclaimer: DISCLAIMER,
  });
});

app.use('/api', notFoundHandler);

const dist = resolve(join(here, '..', '..', 'frontend', 'dist'));
if (existsSync(dist)) {
  app.use(express.static(dist, {
    index: false,
    setHeaders: (res, path) => {
      if (path.endsWith('index.html')) return;
      res.setHeader('Cache-Control', 'public, max-age=3600');
    },
  }));
  app.get('*', (req, res) => {
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Content-Security-Policy',
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'");
    res.sendFile(join(dist, 'index.html'));
  });
} else {
  app.get('/', (req, res) => {
    res.json({
      service: 'SecureFlow AI API',
      note: 'The web client has not been built yet. Run npm run build, or use the Vite dev server on port 5173.',
      docs: '/api/docs',
    });
  });
}

app.use(errorHandler);

const server = app.listen(PORT, () => {
  console.log(`[secureflow] API listening on http://localhost:${PORT}`);
  console.log(`[secureflow] environment: ${process.env.NODE_ENV ?? 'development'}`);
  console.log(`[secureflow] demo mode: ${demoMode ? 'on (synthetic data, known demo accounts)' : 'off'}`);
  console.log(`[secureflow] demo database: ${process.env.SF_DB_PATH ?? 'backend/data/secureflow.db'}`);
  console.log(`[secureflow] website protection: ${websiteProtectionEnabled() ? 'on' : 'off'}`);
});

if (websiteProtectionEnabled()) startWebsiteScheduler();

function shutdown(signal) {
  console.log(`[secureflow] ${signal} received, closing server`);
  server.close(() => {
    try { db.close(); } catch { /* already closed */ }
    rateLimitStore.close?.().catch?.(() => {});
    process.exit(0);
  });
  setTimeout(() => process.exit(0), 4000).unref();
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

export { app };
