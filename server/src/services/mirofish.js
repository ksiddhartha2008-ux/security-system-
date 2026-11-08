import { newId, nowIso, run } from '../db.js';
import { badRequest, notFound } from '../lib/http.js';

/* ------------------------------------------------------------------ *
 * MiroFish integration adapter.
 *
 * MiroFish (github.com/666ghj/MiroFish, AGPL-3.0) is a Flask service that
 * exposes three blueprints: /api/graph, /api/simulation and /api/report.
 * It requires Python 3.11-3.12, an OpenAI compatible LLM key, a Zep Cloud
 * key and the camel-oasis stack. This adapter only speaks to the documented
 * HTTP routes. When MiroFish is not configured it reports that honestly and
 * never fabricates a run.
 * ------------------------------------------------------------------ */

const BASE = () => (process.env.MIROFISH_BASE_URL ?? '').replace(/\/+$/, '');
const API_KEY = () => process.env.MIROFISH_API_KEY ?? '';

export const MIROFISH_CAPABILITIES = [
  { id: 'graph.build', label: 'Build a knowledge graph from seed material', endpoint: 'POST /api/graph/build' },
  { id: 'simulation.create', label: 'Create a simulation for a project', endpoint: 'POST /api/simulation/create' },
  { id: 'simulation.prepare', label: 'Prepare agent profiles and simulation config', endpoint: 'POST /api/simulation/prepare' },
  { id: 'simulation.start', label: 'Start the multi-agent run', endpoint: 'POST /api/simulation/start' },
  { id: 'simulation.status', label: 'Read run status and actions', endpoint: 'GET /api/simulation/<id>/run-status' },
  { id: 'report.generate', label: 'Generate a prediction report', endpoint: 'POST /api/report/generate' },
];

async function request(path, { method = 'GET', body, timeoutMs = 6000 } = {}) {
  const base = BASE();
  if (!base) {
    const err = new Error('MiroFish is not configured. Set MIROFISH_BASE_URL to an isolated MiroFish instance.');
    err.code = 'not_configured';
    throw err;
  }
  let response;
  try {
    response = await fetch(`${base}${path}`, {
      method,
      headers: {
        accept: 'application/json',
        ...(body ? { 'content-type': 'application/json' } : {}),
        ...(API_KEY() ? { authorization: `Bearer ${API_KEY()}` } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    const wrapped = new Error(`MiroFish is unreachable at ${base}: ${err.name === 'TimeoutError' ? 'request timed out' : err.message}`);
    wrapped.code = 'unreachable';
    throw wrapped;
  }
  const text = await response.text();
  let parsed = null;
  try { parsed = text ? JSON.parse(text) : null; } catch { parsed = { raw: text.slice(0, 400) }; }
  if (!response.ok) {
    const message = parsed?.error ?? `MiroFish returned HTTP ${response.status}`;
    const err = new Error(message);
    err.code = 'upstream_error';
    err.status = response.status;
    throw err;
  }
  return parsed;
}

export async function mirofishStatus() {
  const configured = Boolean(BASE());
  const base = {
    configured,
    baseUrl: configured ? BASE() : null,
    reachable: false,
    latencyMs: null,
    license: 'AGPL-3.0',
    runtime: 'Python 3.11-3.12, Flask, camel-oasis, OpenAI compatible LLM, Zep Cloud',
    capabilities: MIROFISH_CAPABILITIES,
    note: 'MiroFish runs as a separate service. SecureFlow imports finished runs; it never stores MiroFish credentials in the browser.',
  };
  if (!configured) {
    return {
      ...base,
      reason: 'MIROFISH_BASE_URL is not set. The simulation lab uses the SecureFlow native engine in the meantime.',
    };
  }
  const started = Date.now();
  try {
    const data = await request('/api/graph/project/list', { timeoutMs: 5000 });
    const projects = data?.data?.projects ?? data?.data ?? [];
    return {
      ...base,
      reachable: true,
      latencyMs: Date.now() - started,
      projects: Array.isArray(projects) ? projects.length : null,
      reason: null,
    };
  } catch (err) {
    return {
      ...base,
      latencyMs: Date.now() - started,
      reason: err.message,
      errorCode: err.code ?? 'unknown',
    };
  }
}

const STATUS_MAP = {
  created: 'draft',
  preparing: 'running',
  ready: 'draft',
  running: 'running',
  completed: 'completed',
  failed: 'failed',
  stopped: 'cancelled',
};

/**
 * Import an existing MiroFish run into SecureFlow as a read only record.
 * The run itself was executed by MiroFish; nothing is re-simulated here.
 */
export async function importMirofishRun({ orgId, userId, remoteId, name }) {
  const id = String(remoteId ?? '').trim();
  if (!/^[A-Za-z0-9_-]{3,64}$/.test(id)) throw badRequest('Enter the MiroFish simulation id (letters, digits, dash or underscore)');
  if (!BASE()) throw badRequest('MiroFish is not configured. Set MIROFISH_BASE_URL first.');

  let detail;
  let runStatus = null;
  try {
    detail = await request(`/api/simulation/${encodeURIComponent(id)}`);
  } catch (err) {
    throw badRequest(`MiroFish could not return simulation ${id}: ${err.message}`);
  }
  try {
    runStatus = await request(`/api/simulation/${encodeURIComponent(id)}/run-status`);
  } catch {
    runStatus = null;
  }

  const remote = detail?.data ?? {};
  const status = STATUS_MAP[remote.status] ?? 'draft';
  const simId = newId('sim');
  const ref = `MIR-${new Date().getUTCFullYear()}-${String(Math.floor(Math.random() * 9000) + 1000)}`;
  const ts = nowIso();
  const summary = {
    synthetic: true,
    source: 'mirofish',
    mirofishSimulationId: id,
    remoteStatus: remote.status ?? null,
    runStatus: runStatus?.data ?? null,
    importedAt: ts,
    note: 'Imported from a separate MiroFish instance. SecureFlow did not execute this run and cannot verify its inputs.',
  };
  run(
    `INSERT INTO simulations (id, org_id, ref, name, scenario, status, engine, config, progress, current_round, total_rounds, risk_score, summary, mirofish_simulation_id, created_by, started_at, finished_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, 'imported-mirofish', ?, 'mirofish', ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?)`,
    simId, orgId, ref, name?.trim() || `MiroFish run ${id}`, status,
    JSON.stringify({ mirofishSimulationId: id }), status === 'completed' ? 100 : 0,
    Number(runStatus?.data?.round ?? 0), Number(runStatus?.data?.total_rounds ?? 0),
    JSON.stringify(summary), id, userId ?? null, remote.created_at ?? null, remote.updated_at ?? null, ts, ts,
  );
  return { id: simId, ref, status, engine: 'mirofish' };
}

export async function remoteRunStatus(remoteId) {
  if (!BASE()) throw badRequest('MiroFish is not configured');
  const data = await request(`/api/simulation/${encodeURIComponent(remoteId)}/run-status`);
  if (!data) throw notFound('MiroFish returned no status for that simulation');
  return data;
}

export const _internals = { BASE, request };
