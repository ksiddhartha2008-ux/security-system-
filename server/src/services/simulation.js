import { all, get, run, newId, nowIso, parseJson, transaction } from '../db.js';
import { ApiError, badRequest, notFound } from '../lib/http.js';
import { broadcast } from '../lib/events.js';

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
    for (const ev of generated) {
      run(
        `INSERT INTO simulation_events (id, org_id, simulation_id, round, agent_id, event_type, severity, message, metadata, occurred_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        newId('sev'), state.orgId, state.simulationId, state.round, ev.agentId, ev.eventType, ev.severity,
        ev.message, JSON.stringify({ ...ev.metadata, synthetic: true }), ts,
      );
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
  };
  const ts = nowIso();
  run(`UPDATE simulations SET status='running', started_at=?, progress=0, current_round=0 WHERE id = ?`, ts, simulationId);
  for (let r = 0; r < sim.total_rounds; r += 1) {
    state.round = r + 1;
    const generated = roundEvents(state.scenarioKey, state, state.agents);
    for (const ev of generated) {
      run(
        `INSERT INTO simulation_events (id, org_id, simulation_id, round, agent_id, event_type, severity, message, metadata, occurred_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        newId('sev'), orgId, simulationId, state.round, ev.agentId, ev.eventType, ev.severity,
        ev.message, JSON.stringify({ ...ev.metadata, synthetic: true }), ts,
      );
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
