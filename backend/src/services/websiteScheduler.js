import { all, get, run, newId, nowIso, transaction } from '../db.js';
import { checkVerification, lapseSite, verificationGraceDays } from './websiteSites.js';
import { createTxtResolver, evaluateTxtRecords, classifyDnsError } from '../lib/dnsTxt.js';
import { challengeRecordValue } from '../lib/websiteNormalize.js';
import { runWebsitePipeline } from './websitePipeline.js';
import { refreshIntegrationHealth } from './websiteHealth.js';
import { applyRetention } from './websiteData.js';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

export const systemReq = (orgId) => ({
  user: { id: null, orgId, email: 'system', role: 'admin' },
  ip: null,
  requestId: null,
});

/**
 * Atomic claim with a lease. BEGIN IMMEDIATE plus the guarded UPDATE means two
 * workers cannot process the same row, even across processes.
 */
export function claimJob({ now = nowIso(), leaseMs = 60_000 } = {}) {
  return transaction(() => {
    const job = get(
      `SELECT * FROM website_jobs
        WHERE next_run_at <= ? AND (lease_until IS NULL OR lease_until < ?)
        ORDER BY next_run_at ASC LIMIT 1`,
      now, now,
    );
    if (!job) return null;
    const lease = new Date(Date.now() + leaseMs).toISOString();
    const result = run(
      `UPDATE website_jobs SET lease_until = ?, attempts = attempts + 1, updated_at = ?
        WHERE id = ? AND (lease_until IS NULL OR lease_until < ?)`,
      lease, nowIso(), job.id, now,
    );
    if (!result.changes) return null;
    return { ...job, lease_until: lease, attempts: job.attempts + 1 };
  });
}

export function enqueue(kind, orgId, { siteId = null, verificationId = null, nextRunAt = nowIso(), payload = {} } = {}) {
  const id = newId('job');
  run(
    `INSERT INTO website_jobs (id, org_id, kind, site_id, verification_id, next_run_at, payload, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    id, orgId, kind, siteId, verificationId, nextRunAt, JSON.stringify(payload), nowIso(), nowIso(),
  );
  return id;
}

function reschedule(job, atMs) {
  run('UPDATE website_jobs SET next_run_at = ?, lease_until = NULL, last_error = NULL, updated_at = ? WHERE id = ?',
    new Date(atMs).toISOString(), nowIso(), job.id);
}

function finish(job) {
  run('DELETE FROM website_jobs WHERE id = ?', job.id);
}

/** Daily ownership re-check. Resolver errors never count as failures. */
export async function reverifySite(site, resolver = createTxtResolver()) {
  if (site.status !== 'verified') return { result: 'skipped' };
  const verification = get(
    `SELECT * FROM domain_verifications WHERE org_id = ? AND site_id = ? AND status IN ('pending','verified')
      ORDER BY created_at DESC LIMIT 1`,
    site.org_id, site.id,
  );
  if (!verification) return { result: 'not_found' };

  let result;
  try {
    const records = await resolver.resolveTxt(verification.record_name);
    result = evaluateTxtRecords(records, challengeRecordValue(verification.token));
  } catch (error) {
    result = classifyDnsError(error);
  }
  const ts = nowIso();
  run('UPDATE domain_verifications SET last_checked_at = ?, last_result = ? WHERE id = ?', ts, result, verification.id);

  if (result === 'ok') {
    run(
      `UPDATE website_sites SET last_verification_ok_at = ?, verification_failing_since = NULL, updated_at = ?
        WHERE id = ? AND org_id = ?`,
      ts, ts, site.id, site.org_id,
    );
    return { result };
  }
  if (result === 'resolver_error') return { result };

  run(
    `UPDATE website_sites SET verification_failing_since = COALESCE(verification_failing_since, ?), updated_at = ?
      WHERE id = ? AND org_id = ?`,
    ts, ts, site.id, site.org_id,
  );
  const fresh = get('SELECT * FROM website_sites WHERE id = ?', site.id);
  if (fresh.verification_failing_since) {
    const failingDays = (Date.now() - new Date(fresh.verification_failing_since).getTime()) / DAY;
    if (failingDays >= verificationGraceDays()) {
      lapseSite(systemReq(site.org_id), fresh);
      return { result, lapsed: true };
    }
  }
  return { result };
}

async function processJob(job, resolver) {
  const orgId = job.org_id;
  if (job.kind === 'verification_pending') {
    const site = get('SELECT * FROM website_sites WHERE id = ? AND org_id = ?', job.site_id, orgId);
    if (!site || site.status !== 'pending_verification') { finish(job); return; }
    const result = await checkVerification(systemReq(orgId), { siteId: site.id, source: 'scheduled', resolver });
    if (result.status === 'verified' || result.status === 'expired' || result.status === 'conflict') {
      finish(job);
      return;
    }
    reschedule(job, Date.now() + 5 * MINUTE);
    return;
  }

  if (job.kind === 'reverify') {
    const site = get('SELECT * FROM website_sites WHERE id = ? AND org_id = ?', job.site_id, orgId);
    if (!site || site.status !== 'verified') { finish(job); return; }
    await reverifySite(site, resolver);
    reschedule(job, Date.now() + DAY);
    return;
  }

  if (job.kind === 'pipeline') {
    runWebsitePipeline(orgId, job.site_id);
    finish(job);
    return;
  }

  if (job.kind === 'health') {
    refreshIntegrationHealth(orgId);
    reschedule(job, Date.now() + HOUR);
    return;
  }

  if (job.kind === 'retention') {
    applyRetention(orgId);
    reschedule(job, Date.now() + DAY);
    return;
  }

  finish(job);
}

/** Process up to `limit` due jobs. Exported so tests can drive it deterministically. */
export async function runDueJobs({ limit = 5, resolver = createTxtResolver(), now = nowIso() } = {}) {
  const processed = [];
  for (let index = 0; index < limit; index += 1) {
    const job = claimJob({ now });
    if (!job) break;
    try {
      await processJob(job, resolver);
      processed.push({ id: job.id, kind: job.kind, ok: true });
    } catch (error) {
      run(
        'UPDATE website_jobs SET lease_until = NULL, last_error = ?, next_run_at = ?, updated_at = ? WHERE id = ?',
        String(error.message).slice(0, 500), new Date(Date.now() + MINUTE).toISOString(), nowIso(), job.id,
      );
      processed.push({ id: job.id, kind: job.kind, ok: false, error: error.message });
    }
  }
  return processed;
}

/** Create the periodic jobs that do not exist yet. Safe to run every minute. */
export function ensureScheduledJobs(now = Date.now()) {
  const orgs = all('SELECT id FROM organizations');
  for (const org of orgs) {
    const pending = all(
      `SELECT s.id, s.created_at FROM website_sites s
        WHERE s.org_id = ? AND s.status = 'pending_verification'
          AND NOT EXISTS (SELECT 1 FROM website_jobs j WHERE j.site_id = s.id AND j.kind = 'verification_pending')`,
      org.id,
    );
    for (const site of pending) {
      enqueue('verification_pending', org.id, { siteId: site.id, nextRunAt: new Date(now + 5 * MINUTE).toISOString() });
    }

    const verified = all(
      `SELECT s.id FROM website_sites s
        WHERE s.org_id = ? AND s.status = 'verified'
          AND NOT EXISTS (SELECT 1 FROM website_jobs j WHERE j.site_id = s.id AND j.kind = 'reverify')`,
      org.id,
    );
    for (const site of verified) {
      enqueue('reverify', org.id, { siteId: site.id, nextRunAt: new Date(now + DAY).toISOString() });
    }

    for (const [kind, interval] of [['health', HOUR], ['retention', DAY]]) {
      const exists = get(`SELECT id FROM website_jobs WHERE org_id = ? AND kind = ? LIMIT 1`, org.id, kind);
      if (!exists) enqueue(kind, org.id, { nextRunAt: new Date(now + interval).toISOString() });
    }
  }
}

let timer = null;
let running = false;

/** Minute tick. Disabled in tests and when the scheduler is switched off. */
export function startWebsiteScheduler() {
  if (process.env.NODE_ENV === 'test') return null;
  if (process.env.SF_WEBSITE_SCHEDULER === 'off') return null;
  if (timer) return timer;
  timer = setInterval(async () => {
    if (running) return;
    running = true;
    try {
      ensureScheduledJobs();
      await runDueJobs({ limit: 3 });
    } catch (error) {
      console.error('[website] scheduler tick failed', error.message);
    } finally {
      running = false;
    }
  }, 60_000);
  timer.unref?.();
  return timer;
}

export function stopWebsiteScheduler() {
  if (timer) clearInterval(timer);
  timer = null;
}
