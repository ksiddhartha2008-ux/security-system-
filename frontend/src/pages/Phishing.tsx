import { useState } from 'react';
import { Link2, ShieldAlert } from 'lucide-react';
import { PageHeader } from '../components/layout';
import {
  Badge, Button, Card, EmptyState, ErrorState, KeyValue, Pagination, RiskBadge, StatusBadge,
  TableSkeleton, useToast, InlineNotice,
} from '../components/ui';
import { useApi } from '../lib/hooks';
import { api, ApiError } from '../lib/api';
import { formatDate, timeAgo } from '../lib/format';
import { useAuth } from '../lib/auth';

type ScanResult = {
  id: string; url: string; domain: string; verdict: string; riskScore: number;
  indicators: { id: string; label: string; weight: number; detail: string }[];
  redirectChain: { url: string; status?: number; error?: string }[];
  reachable: boolean; httpStatus: number | null; contentType: string | null;
  reputation: { providers: string[]; checks: { provider: string; malicious?: number; suspicious?: number; harmless?: number; note?: string; error?: string; abuseConfidenceScore?: number; totalReports?: number }[]; note?: string };
  scannedAt: string; note: string;
};
type History = { data: { id: string; url: string; domain: string; verdict: string; riskScore: number; indicators: { id: string }[]; reachable: boolean; createdAt: string }[]; meta: { page: number; limit: number; total: number; totalPages: number } };

export default function PhishingPage() {
  const { permissions } = useAuth();
  const toast = useToast();
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const history = useApi<History>(`/phishing?page=${page}&limit=15`);

  const scan = async () => {
    setError(null);
    if (!url.trim()) { setError('Enter a URL to scan'); return; }
    setScanning(true);
    setResult(null);
    try {
      const data = await api.post<ScanResult>('/phishing/scan', { url: url.trim() });
      setResult(data);
      history.refresh();
      toast.push(data.verdict === 'malicious' ? 'warn' : 'success', `Scan completed: ${data.verdict.replace('_', ' ')}`, `Risk score ${data.riskScore}/100`);
    } catch (err) {
      const message = err instanceof ApiError ? err.message : 'Scan failed';
      setError(message);
      toast.push('error', 'Scan refused', message);
    } finally { setScanning(false); }
  };

  return (
    <>
      <PageHeader title="Phishing URL scanner" subtitle="Fetch a single page with redirects capped, private address ranges refused and response size limited. Remote HTML is pattern matched, never rendered." />

      <div className="grid" style={{ gridTemplateColumns: '1.35fr 1fr' }}>
        <Card title="Scan a URL" subtitle="http and https only. Loopback, private, link local, multicast and reserved addresses are rejected before any request.">
          <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
            <input className="input mono" style={{ flex: 1, minWidth: 240 }} value={url} onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') scan(); }} placeholder="https://example.com/login" aria-label="URL to scan" />
            <Button variant="primary" onClick={scan} loading={scanning} icon={<Link2 size={14} aria-hidden="true" />}>Scan URL</Button>
          </div>
          {error && <div className="error-box" style={{ marginTop: 12 }} role="alert">{error}</div>}
          <p className="tiny faint" style={{ marginTop: 10 }}>
            The scanner reveals this server's address to the destination host. Only scan URLs you are authorised to inspect.
          </p>

          {result && (
            <div className="stack" style={{ marginTop: 18 }}>
              <div className="row wrap" style={{ gap: 8 }}>
                <Badge tone={result.verdict === 'malicious' ? 'critical' : result.verdict === 'suspicious' ? 'medium' : 'low'} dot>{result.verdict.replace('_', ' ')}</Badge>
                <RiskBadge score={result.riskScore} />
                <StatusBadge status={result.reachable ? 'completed' : 'failed'} />
                <span className="tiny faint">{formatDate(result.scannedAt)}</span>
              </div>
              <p className="mono small" style={{ wordBreak: 'break-all' }}>{result.url}</p>
              <KeyValue items={[
                { label: 'Domain', value: result.domain },
                { label: 'HTTP status', value: result.httpStatus ?? 'No response' },
                { label: 'Content type', value: result.contentType ?? '—' },
                { label: 'Redirects', value: String(Math.max(0, result.redirectChain.length - 1)) },
              ]} />
              {!result.reachable && (
                <InlineNotice tone="warn">
                  The host did not respond inside the scanner limits. The indicators below still apply to the URL itself.
                </InlineNotice>
              )}
              <div>
                <p className="label">Indicators ({result.indicators.length})</p>
                {result.indicators.length === 0 ? <p className="small faint">No heuristic indicator was triggered.</p> : (
                  <div className="stack" style={{ gap: 7, marginTop: 6 }}>
                    {result.indicators.map((indicator) => (
                      <div key={indicator.id} className="row" style={{ gap: 8, alignItems: 'flex-start' }}>
                        <Badge tone={indicator.weight >= 20 ? 'high' : indicator.weight >= 12 ? 'medium' : 'neutral'}>+{indicator.weight}</Badge>
                        <div>
                          <p className="small">{indicator.label}</p>
                          <p className="tiny faint">{indicator.detail}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
              {result.redirectChain.length > 0 && (
                <div>
                  <p className="label">Redirect chain</p>
                  <div className="stack" style={{ gap: 3, marginTop: 4 }}>
                    {result.redirectChain.map((hop, index) => (
                      <p key={`${hop.url}-${index}`} className="mono tiny" style={{ wordBreak: 'break-all' }}>
                        {hop.status ? <span style={{ color: 'var(--color-mint)' }}>{hop.status} </span> : null}{hop.url}
                        {hop.error ? <span style={{ color: 'var(--color-danger-text)' }}> · {hop.error}</span> : null}
                      </p>
                    ))}
                  </div>
                </div>
              )}
              <div>
                <p className="label">Reputation providers</p>
                {result.reputation.checks.length === 0 ? <p className="small faint">{result.reputation.note ?? 'No provider configured.'}</p> : (
                  <div className="stack" style={{ gap: 5, marginTop: 4 }}>
                    {result.reputation.checks.map((check, index) => (
                      <p key={`${check.provider}-${index}`} className="small muted">
                        <strong style={{ color: 'var(--color-ink-strong)' }}>{check.provider}</strong>{' '}
                        {check.error ?? check.note ?? `${check.malicious} malicious · ${check.suspicious} suspicious`}
                        {check.abuseConfidenceScore !== undefined ? ` · abuse confidence ${check.abuseConfidenceScore}%` : ''}
                      </p>
                    ))}
                  </div>
                )}
              </div>
              <p className="tiny faint">{result.note}</p>
            </div>
          )}
        </Card>

        <Card title="What this scan cannot tell you" subtitle="Limits of a single page fetch">
          <ul className="small muted" style={{ margin: 0, paddingLeft: 18, display: 'grid', gap: 8 }}>
            <li>It does not execute JavaScript, so behaviour after load is not observed.</li>
            <li>It does not submit forms or credentials. A page with no password field can still be malicious.</li>
            <li>Reputation is only consulted when VirusTotal or AbuseIPDB keys are configured.</li>
            <li>A low score means no heuristic matched, not that the site is trustworthy.</li>
            <li>Redirect chains stop at three hops. Later hops are recorded as blocked.</li>
          </ul>
          <div className="divider" style={{ margin: '14px 0' }} />
          <div className="row" style={{ gap: 8 }}>
            <ShieldAlert size={15} aria-hidden="true" color="var(--color-amber)" />
            <p className="tiny faint">Reports are stored in this workspace with the indicators that produced them.</p>
          </div>
        </Card>
      </div>

      <Card title="Scan history" subtitle="Most recent first" bodyClass="" className="" >
        {history.loading && !history.data ? <TableSkeleton rows={5} cols={4} /> : history.error ? <ErrorState message={history.error} onRetry={history.refresh} /> : (
          <>
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>Verdict</th><th>URL</th><th>Risk</th><th>Indicators</th><th>Reachable</th><th className="right">Scanned</th></tr></thead>
                <tbody>
                  {history.data?.data.map((scan) => (
                    <tr key={scan.id} className="row-link" onClick={() => setUrl(scan.url)} tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter') setUrl(scan.url); }}>
                      <td><Badge tone={scan.verdict === 'malicious' ? 'critical' : scan.verdict === 'suspicious' ? 'medium' : 'low'}>{scan.verdict.replace('_', ' ')}</Badge></td>
                      <td className="mono tiny truncate-cell" style={{ maxWidth: 380 }}>{scan.url}</td>
                      <td><RiskBadge score={scan.riskScore} /></td>
                      <td className="small muted">{scan.indicators.length}</td>
                      <td><StatusBadge status={scan.reachable ? 'online' : 'offline'} /></td>
                      <td className="right tiny faint">{timeAgo(scan.createdAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {history.data?.data.length === 0 && <EmptyState title="No scans yet" body="Paste a URL above to run the first scan. Results stay in your workspace." icon={<Link2 size={18} aria-hidden="true" />} />}
            {history.data && history.data.data.length > 0 && <Pagination page={history.data.meta.page} totalPages={history.data.meta.totalPages} total={history.data.meta.total} onPage={setPage} />}
          </>
        )}
      </Card>
      {!permissions.canWrite && <p className="tiny faint" style={{ marginTop: 10 }}>Viewer accounts can read scan history but cannot start new scans.</p>}
    </>
  );
}
