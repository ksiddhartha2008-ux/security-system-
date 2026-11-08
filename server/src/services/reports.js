import { all, get, parseJson } from '../db.js';
import { badRequest } from '../lib/http.js';

export const REPORT_TYPES = [
  { key: 'executive', name: 'Executive security summary', description: 'Posture, event volume, open risk and simulation coverage for the selected window.' },
  { key: 'incidents', name: 'Incident report', description: 'Incident lifecycle, severity mix and time to resolution.' },
  { key: 'threats', name: 'Threat detection report', description: 'Deterministic detections, rule coverage and indicator inventory.' },
  { key: 'assets', name: 'Asset risk report', description: 'Inventory by criticality with current risk scores.' },
  { key: 'vulnerabilities', name: 'Vulnerability report', description: 'Open vulnerabilities ordered by CVSS with remediation status.' },
  { key: 'simulations', name: 'Simulation report', description: 'Threat simulation runs, risk scores and recommendations.' },
];

const cell = (v) => String(v ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
const mdTable = (columns, rows) => {
  if (!rows.length) return '_No records in this window._\n';
  return [
    `| ${columns.map((c) => c.label).join(' | ')} |`,
    `| ${columns.map(() => '---').join(' | ')} |`,
    ...rows.map((row) => `| ${columns.map((c) => cell(row[c.key])).join(' | ')} |`),
  ].join('\n') + '\n';
};

const windowClause = (from, to) => {
  const clauses = [];
  const params = [];
  if (from) { clauses.push('created_at >= ?'); params.push(from); }
  if (to) { clauses.push('created_at <= ?'); params.push(to); }
  return { sql: clauses.length ? ` AND ${clauses.join(' AND ')}` : '', params };
};

export function buildReport(orgId, type, params = {}) {
  const meta = REPORT_TYPES.find((t) => t.key === type);
  if (!meta) throw badRequest('Unknown report type');
  const from = params.from ? new Date(params.from).toISOString() : null;
  const to = params.to ? new Date(params.to).toISOString() : null;
  const win = windowClause(from, to);
  const org = get('SELECT name FROM organizations WHERE id = ?', orgId);
  const generatedAt = new Date().toISOString();

  const kpis = [];
  const tables = [];
  const notes = [];

  if (type === 'executive' || type === 'incidents') {
    const incidents = all(
      `SELECT ref, title, severity, priority, status, detected_at, resolved_at FROM incidents
        WHERE org_id = ?${win.sql} ORDER BY detected_at DESC LIMIT 200`,
      orgId, ...win.params,
    );
    const open = incidents.filter((i) => !['resolved', 'closed'].includes(i.status));
    const critical = incidents.filter((i) => i.severity === 'critical').length;
    kpis.push({ label: 'Incidents in window', value: incidents.length });
    kpis.push({ label: 'Still open', value: open.length });
    kpis.push({ label: 'Critical severity', value: critical });
    tables.push({
      title: 'Incidents',
      columns: [
        { key: 'ref', label: 'Reference' }, { key: 'title', label: 'Title' },
        { key: 'severity', label: 'Severity' }, { key: 'status', label: 'Status' },
        { key: 'detected_at', label: 'Detected' },
      ],
      rows: incidents.map((i) => ({ ...i, detected_at: i.detected_at?.slice(0, 16).replace('T', ' ') })),
    });
  }

  if (type === 'executive' || type === 'threats') {
    const detections = all(
      `SELECT title, severity, risk_score, status, detected_at FROM detections
        WHERE org_id = ?${win.sql} ORDER BY detected_at DESC LIMIT 200`,
      orgId, ...win.params,
    );
    const iocs = all('SELECT type, value, threat_type, confidence, status FROM iocs WHERE org_id = ? ORDER BY created_at DESC LIMIT 200', orgId);
    kpis.push({ label: 'Detections in window', value: detections.length });
    kpis.push({ label: 'Open high risk detections', value: detections.filter((d) => d.status === 'open' && d.risk_score >= 70).length });
    kpis.push({ label: 'Indicators tracked', value: iocs.length });
    tables.push({
      title: 'Detections',
      columns: [
        { key: 'title', label: 'Detection' }, { key: 'severity', label: 'Severity' },
        { key: 'risk_score', label: 'Risk' }, { key: 'status', label: 'Status' },
        { key: 'detected_at', label: 'Detected' },
      ],
      rows: detections.map((d) => ({ ...d, detected_at: d.detected_at?.slice(0, 16).replace('T', ' ') })),
    });
    tables.push({
      title: 'Indicators of compromise',
      columns: [
        { key: 'type', label: 'Type' }, { key: 'value', label: 'Value' },
        { key: 'threat_type', label: 'Threat' }, { key: 'confidence', label: 'Confidence' },
      ],
      rows: iocs,
    });
  }

  if (type === 'assets') {
    const assets = all(
      `SELECT name, hostname, ip_address, os, criticality, risk_score, status FROM assets
        WHERE org_id = ? ORDER BY risk_score DESC, name`,
      orgId,
    );
    kpis.push({ label: 'Assets', value: assets.length });
    kpis.push({ label: 'Critical assets', value: assets.filter((a) => a.criticality === 'critical').length });
    kpis.push({ label: 'Average risk score', value: assets.length ? Math.round(assets.reduce((s, a) => s + a.risk_score, 0) / assets.length) : 0 });
    tables.push({
      title: 'Asset inventory',
      columns: [
        { key: 'name', label: 'Asset' }, { key: 'hostname', label: 'Hostname' }, { key: 'ip_address', label: 'IP' },
        { key: 'criticality', label: 'Criticality' }, { key: 'risk_score', label: 'Risk' }, { key: 'status', label: 'Status' },
      ],
      rows: assets,
    });
  }

  if (type === 'vulnerabilities') {
    const vulns = all(
      `SELECT v.cve_id, v.title, v.severity, v.cvss, v.status, v.due_at, a.name AS asset
         FROM vulnerabilities v LEFT JOIN assets a ON a.id = v.asset_id AND a.org_id = v.org_id
        WHERE v.org_id = ? ORDER BY v.cvss DESC`,
      orgId,
    );
    kpis.push({ label: 'Vulnerabilities', value: vulns.length });
    kpis.push({ label: 'Critical or high', value: vulns.filter((v) => ['critical', 'high'].includes(v.severity)).length });
    kpis.push({ label: 'Remediated', value: vulns.filter((v) => v.status === 'remediated').length });
    tables.push({
      title: 'Vulnerabilities by CVSS',
      columns: [
        { key: 'cve_id', label: 'CVE' }, { key: 'title', label: 'Title' }, { key: 'severity', label: 'Severity' },
        { key: 'cvss', label: 'CVSS' }, { key: 'asset', label: 'Asset' }, { key: 'status', label: 'Status' },
      ],
      rows: vulns,
    });
    notes.push('Records are entered by analysts or imported from an external scanner. SecureFlow does not invent scan results.');
  }

  if (type === 'executive' || type === 'simulations') {
    const sims = all(
      `SELECT ref, name, scenario, status, engine, risk_score, total_rounds, created_at FROM simulations
        WHERE org_id = ?${win.sql} ORDER BY created_at DESC LIMIT 100`,
      orgId, ...win.params,
    );
    kpis.push({ label: 'Simulation runs', value: sims.length });
    kpis.push({ label: 'Completed', value: sims.filter((s) => s.status === 'completed').length });
    const scored = sims.filter((s) => s.risk_score !== null);
    kpis.push({ label: 'Mean simulated risk', value: scored.length ? Math.round(scored.reduce((s, x) => s + x.risk_score, 0) / scored.length) : 'n/a' });
    tables.push({
      title: 'Threat simulation runs',
      columns: [
        { key: 'ref', label: 'Reference' }, { key: 'name', label: 'Name' }, { key: 'scenario', label: 'Scenario' },
        { key: 'status', label: 'Status' }, { key: 'risk_score', label: 'Risk' }, { key: 'created_at', label: 'Created' },
      ],
      rows: sims.map((s) => ({ ...s, created_at: s.created_at?.slice(0, 16).replace('T', ' ') })),
    });
    notes.push('Simulation figures are synthetic outcomes produced by the simulation engine. They are not production detections.');
    if (type === 'simulations') {
      const reports = all(
        `SELECT s.ref, r.risk_score, r.findings, r.recommendations FROM simulation_reports r
           JOIN simulations s ON s.id = r.simulation_id WHERE r.org_id = ? ORDER BY r.created_at DESC LIMIT 20`,
        orgId,
      );
      for (const r of reports) {
        const findings = parseJson(r.findings, []);
        const recs = parseJson(r.recommendations, []);
        tables.push({
          title: `Findings for ${r.ref}`,
          columns: [{ key: 'finding', label: 'Finding' }, { key: 'recommendation', label: 'Recommendation' }],
          rows: findings.map((f, i) => ({ finding: f, recommendation: recs[i] ?? '' })),
        });
      }
    }
  }

  if (type === 'executive') {
    const events = all(
      `SELECT severity, COUNT(*) AS count FROM security_events WHERE org_id = ?${win.sql} GROUP BY severity`,
      orgId, ...win.params,
    );
    kpis.unshift({ label: 'Security events in window', value: events.reduce((s, e) => s + e.count, 0) });
    tables.unshift({
      title: 'Events by severity',
      columns: [{ key: 'severity', label: 'Severity' }, { key: 'count', label: 'Events' }],
      rows: events.sort((a, b) => b.count - a.count),
    });
    notes.push('Counts come from the SecureFlow database for the selected window. No figures are estimated.');
  }

  const lines = [
    `# ${meta.name}`,
    '',
    `Organization: ${org?.name ?? 'SecureFlow'}  `,
    `Generated: ${generatedAt}  `,
    `Window: ${from ? from.slice(0, 10) : 'all time'} to ${to ? to.slice(0, 10) : 'now'}`,
    '',
    '## Key figures',
    '',
    ...kpis.map((k) => `- ${k.label}: **${k.value}**`),
    '',
  ];
  for (const table of tables) {
    lines.push(`## ${table.title}`, '', mdTable(table.columns, table.rows), '');
  }
  if (notes.length) lines.push('## Notes', '', ...notes.map((n) => `- ${n}`), '');

  return {
    type,
    title: `${meta.name} - ${(org?.name ?? 'SecureFlow')}`,
    summary: { kpis, tables, notes, window: { from, to }, generatedAt },
    body_md: lines.join('\n'),
  };
}
