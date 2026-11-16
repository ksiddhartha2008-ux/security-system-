import { Activity, Database, FileWarning, KeyRound, ShieldAlert, ShieldCheck } from 'lucide-react';
import { PageHeader } from '../components/layout';
import { MetricCard } from '../components/design';
import { Badge, Card, EmptyState, ErrorState, InlineNotice, TableSkeleton } from '../components/ui';
import { useApi } from '../lib/hooks';
import { timeAgo, type Tone } from '../lib/format';

type Detection = { ruleId: string; title: string; severity: string; riskScore: number; detectedAt: string };
type Protection = {
  generatedAt: string;
  credential: {
    events24h: number; events7d: number; failures24h: number; successes24h: number;
    mfaFailures24h: number; resetRequests24h: number; locked24h: number; denials24h: number; rateLimited24h: number;
    mfa: { enabled: number; total: number };
    detections: Detection[]; apiDetections: Detection[];
    topSources: { address: string; hits: number }[];
  };
  database: {
    events24h: number; authFailures24h: number; privileged24h: number; schemaChanges24h: number;
    exports24h: number; exportedRecords24h: number; detections: Detection[];
    auditSource: { state: string; detail: string };
  };
  sites: { total: number; verified: number; lastEventAt: string | null };
  incidents: { open: number };
  audit: { ok: boolean | null; detail: string; checkedAt?: string };
  policy: { secretsAccepted: boolean; note: string };
};

function toneFor(status: string): Tone {
  const value = status.toUpperCase();
  if (['CRITICAL', 'HIGH'].includes(value)) return 'critical';
  if (['MEDIUM'].includes(value)) return 'amber';
  if (['VERIFIED', 'CONFIGURED'].includes(value)) return 'mint';
  if (['NOT CONFIGURED', 'LOW'].includes(value)) return 'neutral';
  return 'info';
}

function DetectionTable({ rows, empty }: { rows: Detection[]; empty: string }) {
  if (!rows.length) return <EmptyState title="No detections" body={empty} icon={<ShieldCheck size={18} aria-hidden="true" />} />;
  return (
    <div className="table-wrap" tabIndex={0} role="group" aria-label="Scrollable table">
      <table className="data">
        <thead><tr><th>Signal</th><th>Severity</th><th>Risk</th><th className="right">Detected</th></tr></thead>
        <tbody>
          {rows.map((row) => (
            <tr key={`${row.ruleId}-${row.detectedAt}`}>
              <td className="truncate-cell">{row.title}<span className="mono tiny faint" style={{ display: 'block' }}>{row.ruleId}</span></td>
              <td><Badge tone={toneFor(row.severity)}>{row.severity}</Badge></td>
              <td className="mono tiny">{row.riskScore}</td>
              <td className="right tiny faint">{timeAgo(row.detectedAt)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function DataProtectionPage() {
  const overview = useApi<Protection>('/data-protection/overview');
  const data = overview.data;

  return (
    <>
      <PageHeader
        title="Data protection"
        subtitle="Credential and database security built from verified website metadata. Passwords, tokens, cookies and request bodies never reach SecureFlow."
      />

      {overview.loading && !data ? <Card><TableSkeleton rows={6} cols={3} /></Card> : overview.error ? <Card><ErrorState message={overview.error} onRetry={overview.refresh} /></Card> : data && (
        <div className="stack" style={{ gap: 14 }}>
          <InlineNotice tone="info">
            {data.policy.note} The audit chain is {data.audit.ok === false ? 'broken' : data.audit.ok ? 'verified' : 'not checked'}.
            {data.audit.ok === false && <strong> {data.audit.detail}</strong>}
          </InlineNotice>

          <div className="grid grid-4">
            <MetricCard label="Failed sign-ins · 24h" value={data.credential.failures24h} foot={`${data.credential.events24h} authentication events`} icon={<KeyRound size={12} aria-hidden="true" />} />
            <MetricCard label="Credential detections" value={data.credential.detections.length} foot="Open or confirmed website rules" icon={<ShieldAlert size={12} aria-hidden="true" />} />
            <MetricCard label="Database events · 24h" value={data.database.events24h} foot={`${data.database.authFailures24h} failed database sign-ins`} icon={<Database size={12} aria-hidden="true" />} />
            <MetricCard label="Exported records · 24h" value={data.database.exportedRecords24h} foot={`${data.database.exports24h} export event(s)`} icon={<FileWarning size={12} aria-hidden="true" />} />
          </div>

          <div className="grid grid-2">
            <Card title="Credential security" subtitle="Authentication metadata from verified websites" bodyClass="">
              <div className="card-body" style={{ display: 'grid', gap: 10 }}>
                <div className="row wrap" style={{ gap: 8 }}>
                  <Badge tone={data.credential.failures24h > 0 ? 'amber' : 'neutral'}>{data.credential.failures24h} failed</Badge>
                  <Badge tone="neutral">{data.credential.successes24h} succeeded</Badge>
                  <Badge tone="neutral">{data.credential.mfaFailures24h} MFA failures</Badge>
                  <Badge tone="neutral">{data.credential.resetRequests24h} reset requests</Badge>
                  <Badge tone="neutral">{data.credential.locked24h} locked accounts</Badge>
                  <Badge tone="neutral">{data.credential.denials24h} authorisation denials</Badge>
                </div>
                <p className="small muted">
                  MFA coverage: {data.credential.mfa.enabled} of {data.credential.mfa.total} active SecureFlow users.
                  {' '}Website accounts are owned by the protected application; this page never sees their secrets.
                </p>
                {data.credential.topSources.length > 0 && (
                  <div>
                    <p className="tiny faint" style={{ marginBottom: 4 }}>Top sources by failed authentication, masked</p>
                    <div className="row wrap" style={{ gap: 8 }}>
                      {data.credential.topSources.map((source) => (
                        <span key={source.address} className="mono tiny" style={{ color: 'var(--color-muted)' }}>{source.address} · {source.hits}</span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
              <div className="card-foot" style={{ padding: 0 }}>
                <DetectionTable rows={[...data.credential.detections, ...data.credential.apiDetections]} empty="No credential attack pattern reached its threshold for this workspace." />
              </div>
            </Card>

            <Card title="Database security" subtitle="Application-emitted database metadata" bodyClass="">
              <div className="card-body" style={{ display: 'grid', gap: 10 }}>
                <div className="row wrap" style={{ gap: 8 }}>
                  <Badge tone={data.database.authFailures24h > 0 ? 'amber' : 'neutral'}>{data.database.authFailures24h} auth failures</Badge>
                  <Badge tone="neutral">{data.database.privileged24h} privileged operations</Badge>
                  <Badge tone="neutral">{data.database.schemaChanges24h} schema changes</Badge>
                  <Badge tone="neutral">{data.database.exports24h} exports</Badge>
                </div>
                <div className="row" style={{ gap: 8, alignItems: 'flex-start' }}>
                  <Badge tone={toneFor(data.database.auditSource.state)}>{data.database.auditSource.state.toLowerCase()}</Badge>
                  <p className="tiny faint" style={{ flex: 1 }}>{data.database.auditSource.detail}</p>
                </div>
                <p className="tiny faint">
                  This is application-level metadata. It is not a database audit log and does not prove every query executed inside the database.
                </p>
              </div>
              <div className="card-foot" style={{ padding: 0 }}>
                <DetectionTable rows={data.database.detections} empty="No database rule reached its threshold. Send database.* events from the SDK to populate this view." />
              </div>
            </Card>
          </div>

          <Card title="Coverage" subtitle="What is actually connected">
            <div className="grid grid-3">
              <div>
                <p className="tiny faint">Verified websites</p>
                <p style={{ fontWeight: 600 }}>{data.sites.verified} of {data.sites.total}</p>
                <p className="tiny faint">{data.sites.lastEventAt ? `Last event ${timeAgo(data.sites.lastEventAt)}` : 'No events yet'}</p>
              </div>
              <div>
                <p className="tiny faint">Open incidents</p>
                <p style={{ fontWeight: 600 }}>{data.incidents.open}</p>
                <p className="tiny faint">Credential and database detections correlate here</p>
              </div>
              <div>
                <p className="tiny faint">Audit chain</p>
                <p style={{ fontWeight: 600 }}>{data.audit.ok === false ? 'Broken' : data.audit.ok ? 'Verified' : 'Not checked'}</p>
                <p className="tiny faint">{data.audit.detail}</p>
              </div>
            </div>
          </Card>

          <p className="tiny faint">
            <Activity size={12} aria-hidden="true" /> Generated {timeAgo(data.generatedAt)}. SecureFlow does not guarantee that a website or database cannot be compromised; it reduces exposure, detects configured patterns and keeps the evidence auditable.
          </p>
        </div>
      )}
    </>
  );
}
