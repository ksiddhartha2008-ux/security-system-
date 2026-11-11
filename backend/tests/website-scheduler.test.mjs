import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const dir = mkdtempSync(join(tmpdir(), 'sf-website-jobs-'));
const dnsFile = join(dir, 'dns.json');
process.env.NODE_ENV = 'test';
process.env.SF_DATA_DIR = dir;
process.env.SF_DB_PATH = join(dir, 'jobs.db');
process.env.SF_DNS_FAKE_FILE = dnsFile;
process.env.SF_ALLOW_TEST_HOSTNAMES = 'true';
process.env.SF_WEBSITE_VERIFICATION_GRACE_DAYS = '14';

let db;
let services;
let sites;
let scheduler;
let dns;
let auditLib;

const writeDns = (records = {}, errors = {}) => writeFileSync(dnsFile, JSON.stringify({ records, errors }), 'utf8');
const req = { user: { id: 'usr_admin', orgId: 'org_test', email: 'admin@example.test', role: 'admin' }, ip: null, requestId: null };
const now = () => new Date().toISOString();

before(async () => {
  writeDns();
  const dbModule = await import('../src/db.js');
  db = dbModule.db;
  dbModule.migrate();
  dbModule.run(
    `INSERT INTO organizations (id, name, slug, plan, settings, created_at, updated_at)
     VALUES ('org_test', 'Test', 'test', 'team', '{}', ?, ?)`,
    now(), now(),
  );
  dbModule.run(
    `INSERT INTO users (id, org_id, email, name, password_hash, role, status, created_at, updated_at)
     VALUES ('usr_admin', 'org_test', 'admin@example.test', 'Admin', 'x', 'admin', 'active', ?, ?)`,
    now(), now(),
  );
  services = dbModule;
  sites = await import('../src/services/websiteSites.js');
  scheduler = await import('../src/services/websiteScheduler.js');
  dns = await import('../src/lib/dnsTxt.js');
  auditLib = await import('../src/lib/audit.js');
});

after(() => {
  try { db.close(); } catch { /* ignore */ }
  try { rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
});

test('a failed business change rolls back its audit entry', () => {
  const before = services.get('SELECT COUNT(*) AS c FROM audit_logs').c;
  assert.throws(() => services.transaction(() => {
    auditLib.audit(req, 'website.created', 'website_site', 'site_rollback', { hostname: 'x.test' });
    throw new Error('business failure');
  }), /business failure/);
  const after = services.get('SELECT COUNT(*) AS c FROM audit_logs').c;
  assert.equal(after, before, 'audit commits with the business change or not at all');
});

test('a pending verification job verifies the site and then removes itself', async () => {
  const created = sites.createSite(req, { url: 'https://sched.example.test', scope: 'host', criticality: 3 });
  writeDns({ [created.verification.record_name]: [`secureflow-site-verification=${created.verification.token}`] });
  scheduler.enqueue('verification_pending', 'org_test', { siteId: created.site.id, nextRunAt: new Date(Date.now() - 1000).toISOString() });
  const processed = await scheduler.runDueJobs({ limit: 3, now: new Date(Date.now() + 1000).toISOString() });
  assert.equal(processed.length >= 1, true);
  const site = services.get('SELECT * FROM website_sites WHERE id = ?', created.site.id);
  assert.equal(site.status, 'verified');
  const jobs = services.all('SELECT * FROM website_jobs WHERE site_id = ? AND kind = ?', created.site.id, 'verification_pending');
  assert.equal(jobs.length, 0);
});

test('a job lease prevents a second worker from claiming the same row', () => {
  scheduler.enqueue('health', 'org_test', { nextRunAt: new Date(Date.now() - 1000).toISOString() });
  const first = scheduler.claimJob({ now: new Date(Date.now() + 1000).toISOString() });
  assert.ok(first);
  const second = scheduler.claimJob({ now: new Date(Date.now() + 1000).toISOString() });
  assert.equal(second, null, 'the lease blocks a second claim');
  services.run('UPDATE website_jobs SET lease_until = ? WHERE id = ?', new Date(Date.now() - 5000).toISOString(), first.id);
  const third = scheduler.claimJob({ now: new Date(Date.now() + 1000).toISOString() });
  assert.equal(third.id, first.id, 'an expired lease can be reclaimed');
  services.run('DELETE FROM website_jobs WHERE id = ?', first.id);
});

test('daily re-verification clears and then sets the failure marker, and lapses after the grace period', async () => {
  const site = services.get(`SELECT * FROM website_sites WHERE hostname = 'sched.example.test'`);
  const verification = services.get('SELECT * FROM domain_verifications WHERE site_id = ?', site.id);

  writeDns({}, { [verification.record_name]: 'ETIMEOUT' });
  let result = await scheduler.reverifySite(site, dns.createTxtResolver());
  assert.equal(result.result, 'resolver_error');
  assert.equal(services.get('SELECT verification_failing_since FROM website_sites WHERE id = ?', site.id).verification_failing_since, null, 'resolver errors are not failures');

  writeDns({}, { [verification.record_name]: 'ENODATA' });
  result = await scheduler.reverifySite(site, dns.createTxtResolver());
  assert.equal(result.result, 'not_found');
  assert.ok(services.get('SELECT verification_failing_since FROM website_sites WHERE id = ?', site.id).verification_failing_since);

  writeDns({ [verification.record_name]: [`secureflow-site-verification=${verification.token}`] });
  result = await scheduler.reverifySite(site, dns.createTxtResolver());
  assert.equal(result.result, 'ok');
  assert.equal(services.get('SELECT verification_failing_since FROM website_sites WHERE id = ?', site.id).verification_failing_since, null);

  writeDns({}, { [verification.record_name]: 'ENODATA' });
  const failing = services.get('SELECT * FROM website_sites WHERE id = ?', site.id);
  services.run('UPDATE website_sites SET verification_failing_since = ? WHERE id = ?', new Date(Date.now() - 15 * 86400000).toISOString(), site.id);
  result = await scheduler.reverifySite(services.get('SELECT * FROM website_sites WHERE id = ?', site.id), dns.createTxtResolver());
  assert.equal(result.lapsed, true);
  assert.equal(services.get('SELECT status FROM website_sites WHERE id = ?', site.id).status, 'lapsed');

  const notifications = services.all('SELECT * FROM notifications WHERE site_id = ?', site.id);
  assert.equal(notifications.some((row) => row.title.includes('lapsed')), true);
  void failing;
});

test('the scheduler creates periodic jobs without duplicating them', () => {
  scheduler.ensureScheduledJobs();
  scheduler.ensureScheduledJobs();
  const health = services.all(`SELECT * FROM website_jobs WHERE org_id = 'org_test' AND kind = 'health'`);
  const retention = services.all(`SELECT * FROM website_jobs WHERE org_id = 'org_test' AND kind = 'retention'`);
  assert.equal(health.length, 1);
  assert.equal(retention.length, 1);
});
