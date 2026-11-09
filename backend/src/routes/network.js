import { Router } from 'express';
import { z } from 'zod';
import { all, get, run, newId, nowIso } from '../db.js';
import { asyncHandler, created, notFound, ok, pageParams, paginated, validate } from '../lib/http.js';
import { requireAuth, requireRole } from '../lib/auth.js';
import { audit } from '../lib/audit.js';

const router = Router();
router.use(requireAuth);

router.get('/', asyncHandler(async (req, res) => {
  const { limit, page, offset } = pageParams(req, { maxLimit: 200, defaultLimit: 30 });
  const where = ['n.org_id = ?'];
  const params = [req.user.orgId];
  if (req.query.protocol) { where.push('n.protocol = ?'); params.push(String(req.query.protocol)); }
  if (req.query.verdict) { where.push('n.verdict = ?'); params.push(String(req.query.verdict)); }
  if (req.query.assetId) { where.push('n.asset_id = ?'); params.push(String(req.query.assetId)); }
  if (req.query.q) {
    where.push('(n.src_ip LIKE ? OR n.dest_ip LIKE ?)');
    const like = `%${String(req.query.q).slice(0, 60)}%`;
    params.push(like, like);
  }
  const sqlWhere = where.join(' AND ');
  const total = get(`SELECT COUNT(*) c FROM network_events n WHERE ${sqlWhere}`, ...params).c;
  const rows = all(
    `SELECT n.*, a.hostname AS asset_hostname FROM network_events n
       LEFT JOIN assets a ON a.id = n.asset_id AND a.org_id = n.org_id
      WHERE ${sqlWhere} ORDER BY n.occurred_at DESC LIMIT ? OFFSET ?`, ...params, limit, offset,
  );
  return paginated(res, rows.map((n) => ({
    id: n.id, srcIp: n.src_ip, srcPort: n.src_port, destIp: n.dest_ip, destPort: n.dest_port,
    protocol: n.protocol, bytesOut: n.bytes_out, bytesIn: n.bytes_in, direction: n.direction,
    verdict: n.verdict, assetId: n.asset_id, assetHostname: n.asset_hostname, occurredAt: n.occurred_at,
    dataOrigin: n.data_origin,
  })), total, { page, limit });
}));

router.get('/summary', asyncHandler(async (req, res) => {
  const org = req.user.orgId;
  const since = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
  const totals = get(
    `SELECT COUNT(*) flows, COALESCE(SUM(bytes_out),0) bytes_out, COALESCE(SUM(bytes_in),0) bytes_in,
            SUM(CASE WHEN verdict = 'suspicious' THEN 1 ELSE 0 END) suspicious,
            SUM(CASE WHEN verdict = 'blocked' THEN 1 ELSE 0 END) blocked
       FROM network_events WHERE org_id = ?`, org,
  );
  const protocols = all('SELECT protocol, COUNT(*) c, SUM(bytes_out) bytes FROM network_events WHERE org_id = ? GROUP BY protocol ORDER BY c DESC', org);
  const topSources = all(
    `SELECT src_ip, COUNT(*) flows, SUM(bytes_out) bytes FROM network_events WHERE org_id = ?
      GROUP BY src_ip ORDER BY bytes DESC LIMIT 8`, org,
  );
  const topDestinations = all(
    `SELECT dest_ip, COUNT(*) flows, SUM(bytes_out) bytes FROM network_events WHERE org_id = ?
      GROUP BY dest_ip ORDER BY bytes DESC LIMIT 8`, org,
  );
  const topPorts = all(
    `SELECT dest_port, COUNT(*) c FROM network_events WHERE org_id = ? AND dest_port IS NOT NULL
      GROUP BY dest_port ORDER BY c DESC LIMIT 10`, org,
  );
  const recent24 = get('SELECT COUNT(*) c FROM network_events WHERE org_id = ? AND occurred_at >= ?', org, since).c;
  return ok(res, {
    totals: {
      flows: totals.flows, bytesOut: totals.bytes_out, bytesIn: totals.bytes_in,
      suspicious: totals.suspicious ?? 0, blocked: totals.blocked ?? 0, last24h: recent24,
    },
    protocols, topSources, topDestinations, topPorts,
  });
}));

router.post('/', requireRole('analyst', 'admin'), asyncHandler(async (req, res) => {
  const body = validate(z.object({
    srcIp: z.string().trim().min(3).max(64),
    srcPort: z.number().int().min(0).max(65535).optional(),
    destIp: z.string().trim().min(3).max(64),
    destPort: z.number().int().min(0).max(65535).optional(),
    protocol: z.enum(['TCP', 'UDP', 'ICMP', 'TLS', 'DNS', 'HTTP']).default('TCP'),
    bytesOut: z.number().int().min(0).default(0),
    bytesIn: z.number().int().min(0).default(0),
    direction: z.enum(['inbound', 'outbound', 'internal']).default('outbound'),
    verdict: z.enum(['allowed', 'suspicious', 'blocked']).default('allowed'),
    assetId: z.string().trim().max(64).optional(),
    occurredAt: z.string().datetime().optional(),
  }), req.body);
  const id = newId('net');
  run(
    `INSERT INTO network_events (id, org_id, src_ip, src_port, dest_ip, dest_port, protocol, bytes_out, bytes_in, direction, verdict, asset_id, occurred_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    id, req.user.orgId, body.srcIp, body.srcPort ?? null, body.destIp, body.destPort ?? null, body.protocol,
    body.bytesOut, body.bytesIn, body.direction, body.verdict, body.assetId ?? null, body.occurredAt ?? nowIso(), nowIso(),
  );
  audit(req, 'network.event_ingested', 'network_event', id, { srcIp: body.srcIp, destIp: body.destIp });
  return created(res, { id });
}));

export default router;
