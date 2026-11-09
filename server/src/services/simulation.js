import { all, get, run, newId, nowIso, parseJson, transaction } from '../db.js';
import { ApiError, badRequest, notFound } from '../lib/http.js';
import { broadcast } from '../lib/events.js';
import { evaluateRules, refreshAssetRisk } from './detection.js';
import { correlateDetections } from './correlation.js';

/* ------------------------------------------------------------------ *
 * Synthetic multi-agent simulation engine (SecureFlow native).
 * Deterministic per seed: same seed and scenario reproduce the run.
 * Every artefact is labelled synthetic; nothing here touches real hosts.
 * ------------------------------------------------------------------ */

export const DISCLAIMER =
  'Synthetic simulation. Agents act on generated data inside SecureFlow AI. No real system, account or network was contacted.';

export const SCENARIOS = [
  {
    key: 'credential-stuffing',
    name: 'Credential stuffing',
    summary: 'Botnet accounts replay leaked credential pairs against the sign-in service while defenders rate limit and force resets.',
    category: 'identity',
    defaultRounds: 8,
    defaultConfig: { botAccounts: 6, victimAccounts: 40, attemptsPerRound: 9, mfaCoverage: 0.55, rateLimitEnabled: true },
    agents: [
      { name: 'botnet-orchestrator', role: 'attacker', persona: 'Controls a residential proxy pool and rotates source addresses between rounds.' },
      { name: 'combo-list-runner', role: 'attacker', persona: 'Replays email and password pairs harvested from an unrelated breach.' },
      { name: 'signin-service', role: 'target', persona: 'Public authentication endpoint with per IP rate limiting and optional MFA.' },
      { name: 'identity-defender', role: 'defender', persona: 'Watches failure ratios per source and forces credential resets on success.' },
    ],
  },
  {
    key: 'api-abuse',
    name: 'API abuse',
    summary: 'A scraping client walks sequential object identifiers and ignores rate limits while the gateway tightens quotas.',
    category: 'application',
    defaultRounds: 8,
    defaultConfig: { clients: 3, requestsPerRound: 60, rateLimitPerMinute: 100, authRequired: true, pagination: true },
    agents: [
      { name: 'scraper-client', role: 'attacker', persona: 'Iterates integer identifiers and retries aggressively on 429 responses.' },
      { name: 'api-gateway', role: 'target', persona: 'Token bucket limiter at 100 requests per minute per client.' },
      { name: 'partner-integration', role: 'legitimate', persona: 'Well behaved integration used as the baseline traffic shape.' },
      { name: 'platform-defender', role: 'defender', persona: 'Compares per client request shape with the seven day baseline.' },
    ],
  },
  {
    key: 'phishing',
    name: 'Phishing campaign',
    summary: 'A lookalike domain mails eight staff members; clicks and one credential submission drive containment.',
    category: 'email',
    defaultRounds: 7,
    defaultConfig: { recipients: 8, linkDomainAgeDays: 2, clickRate: 0.5, credentialSubmitRate: 0.25, reportRate: 0.4 },
    agents: [
      { name: 'campaign-sender', role: 'attacker', persona: 'Registers a lookalike domain and sends a payroll themed message.' },
      { name: 'mailbox-finance', role: 'target', persona: 'Finance mailbox, receives invoices from unknown senders daily.' },
      { name: 'mailbox-people', role: 'target', persona: 'People operations mailbox, frequently clicks benefits links.' },
      { name: 'mail-gateway', role: 'defender', persona: 'Quarantines on report and rewrites links for detonation.' },
    ],
  },
  {
    key: 'insider-threat',
    name: 'Insider threat',
    summary: 'A departing engineer copies customer records to removable media days before their last working day.',
    category: 'identity',
    defaultRounds: 9,
    defaultConfig: { recordsAccessed: 400, offHours: true, usbEnabled: true, dlpEnabled: true, noticePeriodDays: 12 },
    agents: [
      { name: 'departing-engineer', role: 'insider', persona: 'Resigned eleven days ago, still holds production read access.' },
      { name: 'data-warehouse', role: 'target', persona: 'Customer analytics warehouse with row level audit logging.' },
      { name: 'endpoint-dlp', role: 'defender', persona: 'Flags bulk exports and removable media writes above 50 MB.' },
      { name: 'hr-system', role: 'context', persona: 'Holds the resignation record that should have triggered access review.' },
    ],
  },
  {
    key: 'ransomware',
    name: 'Ransomware',
    summary: 'A loader executes on a workstation, deletes shadow copies and encrypts a file share before the endpoint is isolated.',
    category: 'endpoint',
    defaultRounds: 9,
    defaultConfig: { patientZero: 1, lateralTargets: 4, encryptionRatePerRound: 120, backupsImmutable: true, edrEnabled: true },
    agents: [
      { name: 'loader-process', role: 'attacker', persona: 'Signed binary proxy execution followed by an unsigned payload.' },
      { name: 'workstation-fin-114', role: 'target', persona: 'Finance workstation with mapped access to the shared drive.' },
      { name: 'file-server-02', role: 'target', persona: 'Department file share holding 1.4 TB of documents.' },
      { name: 'edr-agent', role: 'defender', persona: 'Behavioural endpoint protection with isolate host capability.' },
    ],
  },
  {
    key: 'brute-force',
    name: 'Brute-force attack',
    summary: 'A password sprayer hammers the sign-in service from one address while rate limiting and MFA respond.',
    category: 'identity',
    defaultRounds: 7,
    defaultConfig: { attemptsPerRound: 9, targetAccounts: 20, mfaCoverage: 0.45, rateLimitEnabled: true },
    agents: [
      { name: 'spray-client', role: 'attacker', persona: 'Tries common passwords across a list of valid accounts from a single address.' },
      { name: 'signin-service', role: 'target', persona: 'Public authentication endpoint with per IP throttling and MFA.' },
      { name: 'identity-defender', role: 'defender', persona: 'Watches failure ratios and locks the source when the threshold is crossed.' },
    ],
  },
  {
    key: 'malware',
    name: 'Malware infection',
    summary: 'A loader executes on a workstation and drops file encryption before the endpoint agent isolates the host.',
    category: 'endpoint',
    defaultRounds: 8,
    defaultConfig: { encryptionRatePerRound: 110, edrEnabled: true, backupsImmutable: true },
    agents: [
      { name: 'loader-process', role: 'attacker', persona: 'Signed installer proxy execution followed by an unsigned payload.' },
      { name: 'workstation-fin-021', role: 'target', persona: 'Finance workstation with a mapped department share.' },
      { name: 'edr-agent', role: 'defender', persona: 'Behavioural endpoint protection with host isolation.' },
    ],
  },
  {
    key: 'sql-injection',
    name: 'SQL injection attempt',
    summary: 'A client sends UNION based payloads to a search endpoint while the WAF and parameterized queries decide the outcome.',
    category: 'application',
    defaultRounds: 7,
    defaultConfig: { requestsPerRound: 14, wafEnabled: true, parameterizedQueries: false },
    agents: [
      { name: 'injection-client', role: 'attacker', persona: 'Automated scanner sending encoded SQL payloads in query parameters.' },
      { name: 'customer-api', role: 'target', persona: 'Node service exposing /api/customers/search.' },
      { name: 'customer-db', role: 'target', persona: 'PostgreSQL database behind the API with read only credentials.' },
      { name: 'waf', role: 'defender', persona: 'Signature and anomaly inspection at the edge.' },
    ],
  },
  {
    key: 'suspicious-admin',
    name: 'Suspicious administrator login',
    summary: 'A privileged account signs in from an unusual range outside working hours and starts exporting records.',
    category: 'identity',
    defaultRounds: 8,
    defaultConfig: { offHours: true, mfaEnabled: false, exportRows: 120 },
    agents: [
      { name: 'admin-account', role: 'attacker', persona: 'Domain administrator credential used from a new network range.' },
      { name: 'identity-provider', role: 'target', persona: 'Issues sessions and records the source address of each sign-in.' },
      { name: 'siem', role: 'defender', persona: 'Correlates privileged sign-ins with export volume and working hours.' },
    ],
  },
];

export const getScenario = (key) => SCENARIOS.find((s) => s.key === key) ?? null;

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const severityRank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

const scenarioCategory = (eventType) => {
  if (eventType.startsWith('auth.') || eventType.startsWith('web.')) return eventType.startsWith('web.') ? 'application' : 'identity';
  if (eventType.startsWith('email.')) return 'email';
  if (eventType.startsWith('network.')) return 'network';
  if (eventType.startsWith('api.')) return 'application';
  return 'endpoint';
};

const syntheticSourceIp = (simulationId) => {
  const sum = [...simulationId].reduce((total, char) => total + char.charCodeAt(0), 0);
  return `203.0.113.${20 + (sum % 200)}`;
};

/**
 * Mirror a simulation event into the security event pipeline. The dedupe key
 * makes reruns idempotent: the same simulation id, round and index is written
 * once, so detection and dashboard counts cannot double up.
 */
function mirrorSimulationEvent(state, event, index) {
  const dedupeKey = `sim:${state.simulationId}:${state.round}:${index}`;
  run(
    `INSERT OR IGNORE INTO security_events
       (id, org_id, event_type, source, severity, category, title, description, src_ip, dest_ip, user_email, asset_id, raw, status, occurred_at, created_at, data_origin, demo_batch_id, dedupe_key, simulation_id)
     VALUES (?, ?, ?, 'simulation', ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, 'new', ?, ?, 'SIMULATED', NULL, ?, ?)`,
    newId('evt'), state.orgId, event.eventType, event.severity, scenarioCategory(event.eventType),
    event.eventType, event.message, state.sourceIp,
    JSON.stringify({ synthetic: true, simulationId: state.simulationId, round: state.round, agentId: event.agentId }),
    nowIso(), nowIso(), dedupeKey, state.simulationId,
  );
}

function pick(rng, list) {
  return list[Math.floor(rng() * list.length) % list.length];
}

function validateConfig(scenario, config) {
  const merged = { ...scenario.defaultConfig, ...(config ?? {}) };
  const out = {};
  for (const [key, def] of Object.entries(scenario.defaultConfig)) {
    const value = merged[key];
    if (typeof def === 'number') {
      const num = Number(value);
      if (!Number.isFinite(num) || num < 0) throw badRequest(`Config field "${key}" must be a positive number`);
      out[key] = Math.min(num, 100000);
    } else if (typeof def === 'boolean') {
      out[key] = Boolean(value);
    } else {
      out[key] = value;
    }
  }
  return out;
}

export function createSimulation(orgId, userId, payload) {
  const scenario = getScenario(payload.scenario);
  if (!scenario) throw badRequest('Unknown simulation scenario');
  const totalRounds = Math.min(Math.max(Number(payload.totalRounds ?? scenario.defaultRounds), 3), 30);
  const config = validateConfig(scenario, payload.config);
  const seed = Number.isFinite(Number(payload.seed)) ? Number(payload.seed) : Math.floor(Math.random() * 1_000_000);
  const id = newId('sim');
  const ref = `SIM-${new Date().getUTCFullYear()}-${String(Math.floor(Math.random() * 9000) + 1000)}`;
  const ts = nowIso();
  run(
    `INSERT INTO simulations (id, org_id, ref, name, scenario, status, engine, config, progress, current_round, total_rounds, created_by, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, 'draft', 'secureflow-native', ?, 0, 0, ?, ?, ?, ?)`,
    id, orgId, ref, payload.name?.trim() || `${scenario.name} simulation`, scenario.key,
    JSON.stringify({ ...config, seed }), totalRounds, userId, ts, ts,
  );
  const agentRows = scenario.agents.map((a) => {
    const agentId = newId('agt');
    run(
      `INSERT INTO simulation_agents (id, org_id, simulation_id, name, role, persona, status, risk_score, activity_count, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'idle', 0, 0, ?)`,
      agentId, orgId, id, a.name, a.role, a.persona, ts,
    );
    return { id: agentId, ...a, riskScore: 0, activityCount: 0 };
  });
  return { id, ref, scenario: scenario.key, agents: agentRows, totalRounds };
}

function roundEvents(scenarioKey, state, agents) {
  const { rng, round, totalRounds, config } = state;
  const byRole = (role) => agents.filter((a) => a.role === role);
  const out = [];
  const push = (agent, eventType, severity, message, metadata = {}) => {
    out.push({ agentId: agent?.id ?? null, eventType, severity, message, metadata });
  };
  const progress = round / totalRounds;

  if (scenarioKey === 'credential-stuffing') {
    const attackers = byRole('attacker');
    const targets = byRole('target');
    const defenders = byRole('defender');
    const attempts = Math.max(2, Math.round(config.attemptsPerRound * (0.6 + rng() * 0.8)));
    const attacker = attackers[round % Math.max(attackers.length, 1)] ?? agents[0];
    for (let i = 0; i < Math.min(attempts, 12); i += 1) {
      push(attacker, 'auth.failure', 'medium', `Failed sign-in for ${pick(rng, ['j.reyes', 'a.miller', 's.patel', 'l.chen', 'd.okafor'])}@meridian.demo from rotating proxy ${pick(rng, ['203.0.113.44', '198.51.100.23', '192.0.2.77'])}`, { attempt: i + 1, account: `victim_${Math.floor(rng() * config.victimAccounts)}` });
    }
    const success = rng() < 0.22 * (1 - config.mfaCoverage);
    if (success) push(targets[0] ?? agents[0], 'auth.success', 'high', 'Sign-in succeeded with a replayed credential pair and no MFA challenge');
    else if (config.mfaCoverage > 0.3) push(targets[0] ?? agents[0], 'auth.mfa_challenge', 'info', 'MFA challenge blocked a replayed credential pair');
    if (config.rateLimitEnabled && round > 1) push(defenders[0] ?? agents[0], 'auth.rate_limited', 'low', 'Source address throttled after failure ratio exceeded 80 percent');
    if (progress > 0.45) push(defenders[0] ?? agents[0], 'detection.rule_match', 'high', 'Credential stuffing rule fired on 4 accounts from one source');
    if (progress > 0.75) push(defenders[0] ?? agents[0], 'response.credential_reset', 'medium', 'Sessions revoked and passwords reset for the 2 accounts touched');
    return out;
  }

  if (scenarioKey === 'api-abuse') {
    const attacker = byRole('attacker')[0] ?? agents[0];
    const gateway = byRole('target')[0] ?? agents[0];
    const legit = byRole('legitimate')[0] ?? agents[0];
    const defenders = byRole('defender');
    const burst = Math.round(config.requestsPerRound * (0.7 + rng() * 0.9));
    push(attacker, 'api.request', 'low', `${burst} requests in one minute against /v1/customers/{id}`, { burst, endpoint: '/v1/customers/{id}' });
    if (burst > config.rateLimitPerMinute) push(gateway, 'api.rate_limit', 'medium', `${burst - config.rateLimitPerMinute} requests rejected with 429 in the same minute`);
    else push(gateway, 'api.allowed', 'info', `${burst} requests accepted by the token bucket`);
    if (rng() < 0.5) push(attacker, 'api.enumeration', 'high', 'Sequential identifiers requested: 1042, 1043, 1044, 1045');
    if (rng() < 0.4) push(legit, 'api.request', 'info', 'Partner integration requested 12 records within its quota');
    if (progress > 0.5) push(defenders[0] ?? agents[0], 'detection.rule_match', 'medium', 'Request shape diverged from the seven day baseline');
    if (progress > 0.8) push(gateway, 'response.quota_reduced', 'low', 'Client quota reduced to 30 requests per minute pending review');
    return out;
  }

  if (scenarioKey === 'phishing') {
    const sender = byRole('attacker')[0] ?? agents[0];
    const gate = byRole('defender')[0] ?? agents[0];
    const mailboxes = byRole('target');
    if (round === 1) {
      push(sender, 'email.sent', 'high', `Payroll themed message sent to ${config.recipients} recipients from a ${config.linkDomainAgeDays} day old lookalike domain`, { recipients: config.recipients, domainAgeDays: config.linkDomainAgeDays });
      push(gate, 'email.delivered', 'medium', 'Message delivered; lookalike domain not yet on any blocklist');
      return out;
    }
    const mailbox = mailboxes[round % Math.max(mailboxes.length, 1)] ?? agents[0];
    if (rng() < config.clickRate) push(mailbox, 'email.click', 'high', 'Recipient clicked the rewritten link and landed on the credential page');
    if (rng() < config.credentialSubmitRate) push(mailbox, 'email.credential_submit', 'critical', 'Recipient submitted a password to the lookalike domain');
    if (rng() < config.reportRate) push(mailbox, 'email.reported', 'info', 'Recipient reported the message with the add-in');
    if (progress > 0.55) push(gate, 'response.quarantine', 'medium', 'Message purged from all mailboxes after the first report');
    if (progress > 0.8) push(gate, 'response.credential_reset', 'medium', 'Password reset and session revoke issued for the submitting account');
    return out;
  }

  if (scenarioKey === 'insider-threat') {
    const insider = byRole('insider')[0] ?? agents[0];
    const warehouse = byRole('target')[0] ?? agents[0];
    const dlp = byRole('defender')[0] ?? agents[0];
    const rows = Math.round((config.recordsAccessed / Math.max(totalRounds - 2, 1)) * (0.6 + rng() * 0.8));
    push(insider, 'data.export', 'medium', `Exported ${rows} customer rows through the analytics console`, { rows, offHours: config.offHours });
    if (config.offHours && round % 3 === 0) push(warehouse, 'audit.off_hours', 'medium', 'Warehouse query executed outside the normal working window');
    if (rows > 90 && config.dlpEnabled) push(dlp, 'dlp.alert', 'high', `Bulk export above the 90 row threshold flagged by DLP`, { rows });
    if (round > 3 && config.usbEnabled && rng() < 0.5) push(insider, 'device.usb_write', 'high', 'Copy of the export written to removable media');
    if (progress > 0.7) push(dlp, 'detection.rule_match', 'high', 'Departing employee pattern matched: notice period plus bulk export');
    if (progress > 0.85) push(byRole('context')[0] ?? agents[0], 'response.access_review', 'medium', 'Access review opened with HR resignation record as context');
    return out;
  }

  if (scenarioKey === 'brute-force') {
    const attacker = byRole('attacker')[0] ?? agents[0];
    const target = byRole('target')[0] ?? agents[0];
    const defender = byRole('defender')[0] ?? agents[0];
    const attempts = Math.max(3, Math.round(config.attemptsPerRound * (0.7 + rng() * 0.6)));
    for (let i = 0; i < Math.min(attempts, 10); i += 1) {
      push(attacker, 'auth.failure', 'medium', `Password spray attempt ${i + 1} for account ${Math.floor(rng() * config.targetAccounts)} from ${state.sourceIp}`, { accountIndex: Math.floor(rng() * config.targetAccounts) });
    }
    if (rng() < 0.18 * (1 - config.mfaCoverage)) {
      push(target, 'auth.success', 'high', 'Password accepted for a targeted account');
    } else if (config.mfaCoverage > 0.3) {
      push(target, 'auth.mfa_challenge', 'info', 'MFA challenge blocked the sign-in');
    }
    if (config.rateLimitEnabled) push(defender, 'auth.rate_limited', 'low', `Source ${state.sourceIp} throttled after repeated failures`);
    if (progress > 0.5) push(defender, 'detection.rule_match', 'high', 'Brute-force threshold crossed for one source address');
    if (progress > 0.8) push(defender, 'response.block_ip', 'medium', `Source ${state.sourceIp} blocked at the identity edge`);
    return out;
  }

  if (scenarioKey === 'malware') {
    const loader = byRole('attacker')[0] ?? agents[0];
    const target = byRole('target')[0] ?? agents[0];
    const defender = byRole('defender')[0] ?? agents[0];
    if (round === 1) push(loader, 'process.exec', 'high', 'Signed installer launched an unsigned payload on workstation-fin-021');
    if (round === 2) push(target, 'malware.detected', 'critical', 'Endpoint sensor flagged a loader written to the user temp directory');
    if (round >= 2) push(target, 'file.encrypt', 'critical', `${Math.round(config.encryptionRatePerRound * (0.6 + rng() * 0.8))} files encrypted on the mapped department share`);
    if (progress > 0.5 && config.edrEnabled) push(defender, 'edr.detection', 'high', 'Behavioural rule matched mass file rename');
    if (progress > 0.7) push(defender, 'response.isolate_host', 'medium', 'Host isolated by the endpoint agent');
    return out;
  }

  if (scenarioKey === 'sql-injection') {
    const attacker = byRole('attacker')[0] ?? agents[0];
    const target = byRole('target')[0] ?? agents[0];
    const defender = byRole('defender')[0] ?? agents[0];
    const requests = Math.round(config.requestsPerRound * (0.8 + rng() * 0.4));
    push(attacker, 'web.sql_injection', 'critical', `UNION SELECT payload sent to /api/customers/search (${requests} requests)`, { endpoint: '/api/customers/search' });
    push(target, 'web.request', 'low', 'Search endpoint processed the request');
    if (config.wafEnabled && rng() < 0.7) push(defender, 'waf.block', 'medium', 'WAF blocked the payload with 403');
    if (!config.parameterizedQueries && progress > 0.4) push(byRole('target')[1] ?? target, 'db.query_error', 'medium', 'Database returned a syntax error to the application');
    if (progress > 0.6) push(defender, 'detection.rule_match', 'critical', 'SQL injection signature matched');
    return out;
  }

  if (scenarioKey === 'suspicious-admin') {
    const admin = byRole('attacker')[0] ?? agents[0];
    const target = byRole('target')[0] ?? agents[0];
    const defender = byRole('defender')[0] ?? agents[0];
    if (round === 1) push(admin, 'auth.privileged_login', 'high', `Domain administrator signed in from ${state.sourceIp} outside working hours`, { offHours: config.offHours });
    push(target, 'authz.grant', 'medium', 'Administrative role granted to the session');
    if (rng() < 0.6) push(admin, 'data.export', 'high', `${Math.round(config.exportRows * 0.3)} customer records exported`);
    if (progress > 0.5) push(defender, 'detection.rule_match', 'high', 'Privileged login correlated with export volume');
    if (progress > 0.8) push(defender, 'response.session_revoke', 'medium', 'Administrative session revoked pending review');
    return out;
  }

  // ransomware
  const loader = byRole('attacker')[0] ?? agents[0];
  const ws = byRole('target')[0] ?? agents[0];
  const fileServer = byRole('target')[1] ?? ws;
  const edr = byRole('defender')[0] ?? agents[0];
  if (round === 1) push(loader, 'process.exec', 'high', 'Unsigned payload executed through a signed installer on workstation-fin-114');
  if (round === 2) push(ws, 'process.shadow_copy_delete', 'critical', 'vssadmin delete shadows /all executed with elevated token');
  if (round >= 2) {
    const files = Math.round(config.encryptionRatePerRound * (0.5 + rng()));
    push(ws, 'file.encrypt', 'critical', `${files} files renamed with a .locked extension on the mapped share`, { files });
    if (round > 3 && rng() < 0.6) push(fileServer, 'file.encrypt', 'critical', 'Encryption activity detected on file-server-02 share');
  }
  if (round >= 3 && config.edrEnabled) push(edr, 'edr.detection', 'high', 'Behavioural rule matched: shadow copy deletion followed by mass rename');
  if (progress > 0.6) push(edr, 'response.isolate_host', 'medium', 'Host isolated from the network by the endpoint agent');
  if (progress > 0.85) push(edr, 'response.restore', 'low', config.backupsImmutable ? 'Restore started from immutable backup snapshot' : 'Restore attempted but backups were reachable from the encrypted host');
  return out;
}

function computeOutcome(scenarioKey, state, events) {
  const { config, totalRounds } = state;
  const count = (t) => events.filter((e) => e.eventType === t).length;
  const worst = events.reduce((acc, e) => (severityRank[e.severity] > severityRank[acc] ? e.severity : acc), 'info');
  let metrics = {};
  let findings = [];
  let recommendations = [];
  let riskScore = 50;

  if (scenarioKey === 'credential-stuffing') {
    const failures = count('auth.failure');
    const successes = count('auth.success');
    const blocked = count('auth.rate_limited') + count('auth.mfa_challenge');
    metrics = { attempts: failures, successfulLogins: successes, blockedChallenges: blocked, mfaCoverage: config.mfaCoverage };
    riskScore = Math.min(98, 45 + successes * 14 + Math.round(failures / 6) - Math.round(blocked * 1.5));
    findings = [
      `${failures} synthetic sign-in attempts were generated across ${totalRounds} rounds.`,
      successes > 0 ? `${successes} attempt(s) succeeded because the replay had no MFA challenge.` : 'No replay succeeded; MFA and rate limiting held.',
      `${blocked} attempt(s) were stopped by MFA challenges or rate limiting.`,
    ];
    recommendations = [
      config.mfaCoverage < 0.8 ? 'Raise MFA coverage above 80 percent for all interactive sign-ins.' : 'Keep MFA mandatory and review exemption list quarterly.',
      'Add breached password detection at sign-in and force a reset on match.',
      'Alert on failure ratios above 80 percent per source across more than three accounts.',
    ];
  } else if (scenarioKey === 'api-abuse') {
    const requests = count('api.request') * Math.round(config.requestsPerRound);
    const limited = count('api.rate_limit');
    metrics = { estimatedRequests: requests, rateLimitEvents: limited, enumerationEvents: count('api.enumeration'), quota: config.rateLimitPerMinute };
    riskScore = Math.min(96, 38 + Math.round(limited * 2.5) + count('api.enumeration') * 6 - (config.authRequired ? 8 : 0));
    findings = [
      `The simulated client issued roughly ${requests} requests, far above the ${config.rateLimitPerMinute} per minute quota.`,
      `${limited} minute window(s) hit the token bucket and returned 429 responses.`,
      config.pagination ? 'Pagination limits the exposure of sequential identifiers but did not stop enumeration.' : 'Missing pagination allowed full enumeration in a few rounds.',
    ];
    recommendations = [
      'Enforce per client quotas with server side counters, not client hints.',
      'Use opaque identifiers so sequential enumeration returns nothing useful.',
      'Alert when a client requests more than 5x its seven day median.',
    ];
  } else if (scenarioKey === 'phishing') {
    const clicks = count('email.click');
    const submits = count('email.credential_submit');
    const reports = count('email.reported');
    metrics = { recipients: config.recipients, clicks, credentialSubmissions: submits, reports };
    riskScore = Math.min(97, 40 + clicks * 7 + submits * 16 - reports * 3);
    findings = [
      `Of ${config.recipients} recipients, ${clicks} clicked and ${submits} submitted a password.`,
      `${reports} recipient(s) reported the message, which triggered quarantine.`,
      `The sending domain was ${config.linkDomainAgeDays} day(s) old at delivery time.`,
    ];
    recommendations = [
      'Block newly registered lookalike domains at the mail gateway.',
      'Rewriting links helped detection; keep it enabled for external senders.',
      'Run a short targeted awareness note for the two teams that clicked most.',
    ];
  } else if (scenarioKey === 'insider-threat') {
    const rows = events.filter((e) => e.eventType === 'data.export').reduce((s, e) => s + (e.metadata.rows ?? 0), 0);
    const usb = count('device.usb_write');
    const alerts = count('dlp.alert');
    metrics = { rowsExported: rows, usbWrites: usb, dlpAlerts: alerts, noticePeriodDays: config.noticePeriodDays };
    riskScore = Math.min(95, 35 + Math.round(rows / 25) + usb * 9 - alerts * 2);
    findings = [
      `${rows} synthetic customer rows were exported over ${totalRounds} rounds, ${config.offHours ? 'mostly outside working hours' : 'during working hours'}.`,
      `${usb} write(s) to removable media were recorded.`,
      `${alerts} DLP alert(s) fired; the resignation record was not linked to access review automatically.`,
    ];
    recommendations = [
      'Trigger an access review the moment a resignation is recorded in HR.',
      'Require approval for exports above the departmental baseline.',
      'Block removable media on endpoints holding customer data unless explicitly exempted.',
    ];
  } else if (scenarioKey === 'brute-force') {
    const failures = count('auth.failure');
    const success = count('auth.success');
    const blocked = count('auth.rate_limited') + count('auth.mfa_challenge');
    metrics = { attempts: failures, successfulLogins: success, blocked, mfaCoverage: config.mfaCoverage };
    riskScore = Math.min(97, 42 + success * 18 + Math.round(failures / 5) - blocked * 2);
    findings = [
      `${failures} failed authentication attempts were generated from one source across ${totalRounds} rounds.`,
      success > 0 ? `${success} attempt(s) succeeded before the source was contained.` : 'No attempt succeeded; MFA and throttling held.',
      `${blocked} attempt(s) were challenged or throttled.`,
    ];
    recommendations = [
      'Lock the source after a failure ratio threshold, not only after a fixed count.',
      'Require MFA for every interactive account.',
      'Alert on one source touching more than three accounts.',
    ];
  } else if (scenarioKey === 'malware') {
    const encrypted = events.filter((e) => e.eventType === 'file.encrypt').reduce((sum, e) => sum + (e.metadata.files ?? 0), 0);
    const detected = count('malware.detected');
    const isolated = count('response.isolate_host');
    metrics = { filesEncrypted: encrypted, malwareDetections: detected, hostIsolated: isolated > 0, immutableBackups: config.backupsImmutable };
    riskScore = Math.min(99, 55 + Math.round(encrypted / 40) + detected * 4 - (isolated ? 12 : 0));
    findings = [
      `${encrypted} synthetic files were encrypted after the loader executed.`,
      `${detected} malware verdict(s) were raised by the endpoint sensor.`,
      isolated ? 'The host was isolated and the run ended with containment.' : 'The host was never isolated.',
    ];
    recommendations = [
      'Block unsigned payloads from user writable directories.',
      'Alert on mass file rename and shadow copy deletion.',
      'Keep an immutable backup copy and test restores.',
    ];
  } else if (scenarioKey === 'sql-injection') {
    const attempts = count('web.sql_injection');
    const blocked = count('waf.block');
    metrics = { injectionAttempts: attempts, wafBlocks: blocked, parameterizedQueries: config.parameterizedQueries, wafEnabled: config.wafEnabled };
    riskScore = Math.min(96, 45 + attempts * 8 + (config.parameterizedQueries ? 0 : 18) - (config.wafEnabled ? 6 : 0));
    findings = [
      `${attempts} SQL injection payload(s) reached the search endpoint.`,
      `${blocked} request(s) were blocked by the WAF.`,
      config.parameterizedQueries ? 'Parameterized queries prevented payload execution.' : 'The simulated query layer used string concatenation.',
    ];
    recommendations = [
      'Use parameterized queries for every database call.',
      'Keep WAF signatures current and alert on repeated blocks from one source.',
      'Run a code review of query construction in the search service.',
    ];
  } else if (scenarioKey === 'suspicious-admin') {
    const logins = count('auth.privileged_login');
    const exports = count('data.export');
    const revoked = count('response.session_revoke');
    metrics = { privilegedLogins: logins, exports, sessionRevoked: revoked > 0, mfaEnabled: config.mfaEnabled };
    riskScore = Math.min(97, 48 + logins * 14 + exports * 6 - (config.mfaEnabled ? 12 : 0) - (revoked ? 8 : 0));
    findings = [
      `${logins} privileged sign-in(s) occurred outside the normal pattern.`,
      `${exports} export event(s) followed the administrative session.`,
      config.mfaEnabled ? 'MFA was enabled for the administrative account.' : 'The administrative account had no second factor.',
    ];
    recommendations = [
      'Require phishing resistant MFA for privileged accounts.',
      'Alert on administrative sign-ins from new network ranges.',
      'Gate bulk exports behind a second approval.',
    ];
  } else {
    const encrypted = events.filter((e) => e.eventType === 'file.encrypt').reduce((s, e) => s + (e.metadata.files ?? 0), 0);
    const isolated = count('response.isolate_host');
    const shadowDelete = count('process.shadow_copy_delete');
    metrics = { filesEncrypted: encrypted, shadowCopyDeletions: shadowDelete, hostIsolated: isolated > 0, immutableBackups: config.backupsImmutable };
    riskScore = Math.min(99, 55 + Math.round(encrypted / 40) + shadowDelete * 6 - (isolated ? 14 : 0) - (config.backupsImmutable ? 0 : 8));
    findings = [
      `${encrypted} synthetic files were encrypted before containment.`,
      shadowDelete > 0 ? 'Shadow copies were deleted, removing the fastest local recovery path.' : 'No shadow copy deletion was observed.',
      isolated ? 'The endpoint agent isolated the host and a backup restore followed.' : 'The host was never isolated; encryption continued to the end of the run.',
      config.backupsImmutable ? 'Immutable backups remained available for restore.' : 'Backups were reachable from the compromised host.',
    ];
    recommendations = [
      'Alert on shadow copy deletion; it is a high signal precursor.',
      'Keep at least one backup copy offline or immutable and test restores quarterly.',
      'Enforce application control so unsigned loaders cannot execute from user profiles.',
    ];
  }

  const narrative = [
    `Simulated ${totalRounds} rounds of the ${scenarioKey} scenario with ${events.length} generated events.`,
    `Highest severity reached: ${worst}. Deterministic score: ${riskScore}/100.`,
    ...findings,
    DISCLAIMER,
  ].join(' ');

  return { riskScore, findings, recommendations, metrics, narrative, worstSeverity: worst };
}

const drivers = new Map();

function loadAgents(sim) {
  return all('SELECT * FROM simulation_agents WHERE simulation_id = ? ORDER BY created_at', sim.id).map((a) => ({
    id: a.id, name: a.name, role: a.role, persona: a.persona, status: a.status, riskScore: a.risk_score,
    activityCount: a.activity_count, lastAction: a.last_action,
  }));
}

export function startSimulation(orgId, simulationId) {
  const sim = get('SELECT * FROM simulations WHERE id = ? AND org_id = ?', simulationId, orgId);
  if (!sim) throw notFound('Simulation not found');
  if (sim.status === 'running') throw badRequest('Simulation is already running');
  if (sim.status === 'completed') throw badRequest('Simulation already completed; create a new run to repeat it');
  const scenario = getScenario(sim.scenario);
  if (!scenario) throw badRequest('Scenario definition missing');
  const config = parseJson(sim.config, {});
  const agents = loadAgents(sim);

  transaction(() => {
    run('DELETE FROM simulation_events WHERE simulation_id = ?', sim.id);
    run('DELETE FROM simulation_reports WHERE simulation_id = ?', sim.id);
    run(`UPDATE simulation_agents SET status='idle', risk_score=0, activity_count=0, last_action=NULL WHERE simulation_id = ?`, sim.id);
    run(
      `UPDATE simulations SET status='running', progress=0, current_round=0, risk_score=NULL, summary='{}', error=NULL,
       started_at=?, finished_at=NULL, updated_at=? WHERE id = ? AND org_id = ?`,
      nowIso(), nowIso(), sim.id, orgId,
    );
  });

  const state = {
    rng: mulberry32(Number(config.seed ?? 1)),
    round: 0,
    totalRounds: sim.total_rounds,
    config,
    events: [],
    orgId,
    simulationId: sim.id,
    agents,
    scenarioKey: sim.scenario,
    sourceIp: syntheticSourceIp(sim.id),
    actorId: sim.created_by ?? null,
  };

  tick(state);
  return { id: sim.id, status: 'running' };
}

function tick(state) {
  const sim = get('SELECT * FROM simulations WHERE id = ?', state.simulationId);
  if (!sim || sim.status !== 'running') return;
  state.round += 1;
  const generated = roundEvents(state.scenarioKey, state, state.agents);
  const ts = nowIso();
  transaction(() => {
    for (const [index, ev] of generated.entries()) {
      run(
        `INSERT INTO simulation_events (id, org_id, simulation_id, round, agent_id, event_type, severity, message, metadata, occurred_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        newId('sev'), state.orgId, state.simulationId, state.round, ev.agentId, ev.eventType, ev.severity,
        ev.message, JSON.stringify({ ...ev.metadata, synthetic: true }), ts,
      );
      mirrorSimulationEvent(state, ev, index);
      state.events.push(ev);
      if (ev.agentId) {
        const weight = severityRank[ev.severity] >= 3 ? 8 : 3;
        run(
          `UPDATE simulation_agents SET activity_count = activity_count + 1, last_action = ?, status = 'active', risk_score = MIN(100, risk_score + ?) WHERE id = ?`,
          ev.message, weight, ev.agentId,
        );
      }
    }
    const progress = Math.round((state.round / state.totalRounds) * 100);
    run('UPDATE simulations SET current_round = ?, progress = ?, updated_at = ? WHERE id = ?',
      state.round, Math.min(progress, 99), ts, state.simulationId);
  });
  broadcast(state.orgId, 'simulation.round', {
    simulationId: state.simulationId, round: state.round, totalRounds: state.totalRounds,
    events: generated.slice(0, 6), progress: Math.round((state.round / state.totalRounds) * 100),
  });

  if (state.round >= state.totalRounds) {
    finish(state);
    return;
  }
  const delay = Math.max(220, Math.min(900, Number(state.config.roundDelayMs) || 650));
  const timer = setTimeout(() => tick(state), delay);
  drivers.set(state.simulationId, timer);
}

function finish(state) {
  const outcome = computeOutcome(state.scenarioKey, state, state.events);
  const ts = nowIso();
  transaction(() => {
    run(
      `INSERT INTO simulation_reports (id, org_id, simulation_id, risk_score, findings, recommendations, narrative, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      newId('srep'), state.orgId, state.simulationId, outcome.riskScore,
      JSON.stringify(outcome.findings), JSON.stringify(outcome.recommendations), outcome.narrative, ts,
    );
    run(
      `UPDATE simulations SET status='completed', progress=100, risk_score=?, summary=?, finished_at=?, updated_at=? WHERE id = ?`,
      outcome.riskScore, JSON.stringify({
        metrics: outcome.metrics, findings: outcome.findings, worstSeverity: outcome.worstSeverity,
        eventCount: state.events.length, synthetic: true, disclaimer: DISCLAIMER,
      }), ts, ts, state.simulationId,
    );
    run(`UPDATE simulation_agents SET status='idle' WHERE simulation_id = ?`, state.simulationId);
  });
  drivers.delete(state.simulationId);
  try {
    evaluateRules(state.orgId, { dataOrigin: 'SIMULATED' });
    correlateDetections(state.orgId, { limit: 5, actorId: state.actorId });
    refreshAssetRisk(state.orgId);
  } catch (err) {
    console.error('[simulation] post-run detection failed', err.message);
  }
  broadcast(state.orgId, 'simulation.finished', { simulationId: state.simulationId, riskScore: outcome.riskScore });
}

export function cancelSimulation(orgId, simulationId) {
  const sim = get('SELECT * FROM simulations WHERE id = ? AND org_id = ?', simulationId, orgId);
  if (!sim) throw notFound('Simulation not found');
  if (sim.status !== 'running') throw badRequest('Only a running simulation can be cancelled');
  const timer = drivers.get(simulationId);
  if (timer) clearTimeout(timer);
  drivers.delete(simulationId);
  run(`UPDATE simulations SET status='cancelled', finished_at=?, updated_at=? WHERE id = ?`, nowIso(), nowIso(), simulationId);
  broadcast(orgId, 'simulation.cancelled', { simulationId });
  return { id: simulationId, status: 'cancelled' };
}

/** Run every round synchronously (used by the seeder and by tests). */
export function runToCompletionSync(orgId, simulationId) {
  const sim = get('SELECT * FROM simulations WHERE id = ? AND org_id = ?', simulationId, orgId);
  if (!sim) throw notFound('Simulation not found');
  const scenario = getScenario(sim.scenario);
  const config = parseJson(sim.config, {});
  const agents = loadAgents(sim);
  const state = {
    rng: mulberry32(Number(config.seed ?? 1)), round: 0, totalRounds: sim.total_rounds,
    config, events: [], orgId, simulationId, agents, scenarioKey: sim.scenario,
    sourceIp: syntheticSourceIp(sim.id), actorId: sim.created_by ?? null,
  };
  const ts = nowIso();
  run(`UPDATE simulations SET status='running', started_at=?, progress=0, current_round=0 WHERE id = ?`, ts, simulationId);
  for (let r = 0; r < sim.total_rounds; r += 1) {
    state.round = r + 1;
    const generated = roundEvents(state.scenarioKey, state, state.agents);
    for (const [index, ev] of generated.entries()) {
      run(
        `INSERT INTO simulation_events (id, org_id, simulation_id, round, agent_id, event_type, severity, message, metadata, occurred_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        newId('sev'), orgId, simulationId, state.round, ev.agentId, ev.eventType, ev.severity,
        ev.message, JSON.stringify({ ...ev.metadata, synthetic: true }), ts,
      );
      mirrorSimulationEvent(state, ev, index);
      state.events.push(ev);
      if (ev.agentId) {
        run(`UPDATE simulation_agents SET activity_count = activity_count + 1, last_action = ?, risk_score = MIN(100, risk_score + ?) WHERE id = ?`,
          ev.message, severityRank[ev.severity] >= 3 ? 8 : 3, ev.agentId);
      }
    }
  }
  run('UPDATE simulations SET current_round = ?, progress = 99 WHERE id = ?', sim.total_rounds, simulationId);
  finish(state);
  return getSimulationDetail(orgId, simulationId);
}

export function getSimulationDetail(orgId, id) {
  const sim = get('SELECT * FROM simulations WHERE id = ? AND org_id = ?', id, orgId);
  if (!sim) throw notFound('Simulation not found');
  const agents = all('SELECT * FROM simulation_agents WHERE simulation_id = ? ORDER BY risk_score DESC, name', id).map((a) => ({
    id: a.id, name: a.name, role: a.role, persona: a.persona, status: a.status,
    riskScore: a.risk_score, activityCount: a.activity_count, lastAction: a.last_action,
  }));
  const events = all('SELECT * FROM simulation_events WHERE simulation_id = ? ORDER BY round, occurred_at', id).map((e) => ({
    id: e.id, round: e.round, agentId: e.agent_id, type: e.event_type, severity: e.severity,
    message: e.message, metadata: parseJson(e.metadata, {}), occurredAt: e.occurred_at,
  }));
  const reportRow = get('SELECT * FROM simulation_reports WHERE simulation_id = ?', id);
  return {
    id: sim.id,
    ref: sim.ref,
    name: sim.name,
    scenario: sim.scenario,
    scenarioName: getScenario(sim.scenario)?.name ?? sim.scenario,
    status: sim.status,
    engine: sim.engine,
    config: parseJson(sim.config, {}),
    progress: sim.progress,
    currentRound: sim.current_round,
    totalRounds: sim.total_rounds,
    riskScore: sim.risk_score,
    summary: parseJson(sim.summary, {}),
    error: sim.error,
    synthetic: true,
    disclaimer: DISCLAIMER,
    createdAt: sim.created_at,
    startedAt: sim.started_at,
    finishedAt: sim.finished_at,
    agents,
    events,
    report: reportRow ? {
      id: reportRow.id, riskScore: reportRow.risk_score,
      findings: parseJson(reportRow.findings, []), recommendations: parseJson(reportRow.recommendations, []),
      narrative: reportRow.narrative, createdAt: reportRow.created_at,
    } : null,
  };
}

/** Simulations left running by a restart are marked failed instead of pretending to run. */
export function recoverInterruptedSimulations() {
  const rows = all(`SELECT id, org_id FROM simulations WHERE status = 'running'`);
  for (const row of rows) {
    run(`UPDATE simulations SET status='failed', error=?, updated_at=? WHERE id = ?`,
      'Server restarted while the simulation was running. Start a new run.', nowIso(), row.id);
    broadcast(row.org_id, 'simulation.failed', { simulationId: row.id, reason: 'server_restart' });
  }
  return rows.length;
}

export function assertScenario(key) {
  if (!getScenario(key)) throw new ApiError(400, 'bad_request', 'Unknown scenario');
  return getScenario(key);
}
