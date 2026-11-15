import { useState } from 'react';
import {
  Activity, AlertTriangle, CheckCircle2, Cloud, Fingerprint, Globe2, Network, Plus,
  Radar, RefreshCw, Server, ShieldCheck, ShieldOff, Wifi, XCircle,
} from 'lucide-react';
import { PageHeader } from '../components/layout';
import { MetricCard } from '../components/design';
import {
  Badge, Button, Card, EmptyState, ErrorState, Field, InlineNotice, KeyValue, Modal,
  StatusBadge, TableSkeleton, Tabs, TabPanel, useToast,
} from '../components/ui';
import { useApi } from '../lib/hooks';
import { api, ApiError } from '../lib/api';
import { formatDate, timeAgo, type Tone } from '../lib/format';
import { useAuth } from '../lib/auth';

type Layer = { key: string; name: string; status: string; detail: string };
type Provider = {
  key: string; name: string; kind: string; status: string; detail: string;
  available: boolean; applyEnabled: boolean; lastSyncAt?: string | null;
};
type FirewallAction = {
  id: string; providerKey: string; type: string; targetIp: string | null; reason: string;
  riskClass: string; status: string; approvalRequired: boolean; requestedBy: string | null;
  expiresAt: string | null; permanent: boolean; verification: Record<string, unknown>;
  error: string | null; createdAt: string;
};
type Rule = {
  id: string; providerKey: string; cidr: string; action: string; state: string;
  expiresAt: string | null; createdAt: string;
};
type Address = {
  id: string; masked: string; family: string; scope: string; interface: string; hostname: string;
  verified: boolean; isManagement: boolean; fingerprint: string | null; fingerprintAvailable: boolean;
  vaulted: boolean; lastSeenAt: string;
};
type Overview = {
  layers: Layer[];
  infra: { total: number; public: number; private: number; management: number; vaultConfigured: boolean; fingerprintConfigured: boolean };
  firewall: { providers: Provider[]; applyEnabled: boolean; activeRules: number; pendingActions: number; note: string };
  collectors: { id: string; kind: string; name: string; health: string; lastSeenAt: string | null }[];
  endpoints: { total: number; online: number; stale: number };
  eventCounts: Record<string, number>;
  pendingApprovals: number;
  recentActions: FirewallAction[];
  origin: Record<string, unknown>;
};
type AddressPayload = {
  addresses: Address[];
  summary: Overview['infra'];
  origin: Record<string, unknown>;
};
type EndpointPayload = {
  agents: { id: string; provider: string; agentId: string; hostname: string; os: string | null; ipMasked: string | null; status: string; lastSeenAt: string | null }[];
  collectors: Overview['collectors'];
  clamav: { configured: boolean; status: string };
  malwareScans: { id: string; filename: string; caseRef: string; status: string; scanStatus: string; scanDetail: string | null; createdAt: string }[];
};
type Policy = { id: string; key: string; enabled: boolean; mode: string; config: Record<string, unknown> };
type IntegrationCard = {
  key: string; name: string; layer: string; category: string; docs: string;
  state: string; ok: boolean; detail: string; latencyMs: number | null; version: string | null;
  lastCheckedAt: string | null; lastSuccessAt: string | null; lastFailureAt: string | null;
  history: { state: string; ok: boolean; checkedAt: string; latencyMs: number | null }[];
  requirements: string[]; missing: string[]; nextAction: string;
  setup: { windows: string[]; linux: string[]; cloud: string[] };
};
type HealthPayload = { integrations: IntegrationCard[]; counts: Record<string, number> };

function toneFor(status: string): Tone {
  const value = status.toUpperCase();
  if (['VERIFIED', 'SUCCEEDED', 'ONLINE'].includes(value)) return 'mint';
  if (['CONNECTED', 'CONFIGURED', 'EXECUTING', 'VERIFYING', 'APPROVED'].includes(value)) return 'info';
  if (['DEGRADED', 'AWAITING_APPROVAL', 'PENDING', 'STALE', 'CONNECTED - NO RECENT EVENTS'].includes(value)) return 'amber';
  if (['ERROR', 'FAILED'].includes(value)) return 'critical';
  if (['UNAVAILABLE', 'BLOCKED', 'REJECTED', 'EXPIRED', 'ROLLED_BACK', 'DISABLED', 'NOT CONFIGURED'].includes(value)) return 'neutral';
  return 'neutral';
}

function statusLabel(status: string) {
  return status.replaceAll('_', ' ').toLowerCase();
}

export default function TriShieldPage() {
  const { permissions, features } = useAuth();
  const flags = features.trishield;
  const toast = useToast();
  const [tab, setTab] = useState<'overview' | 'perimeter' | 'endpoints' | 'integrations' | 'ip' | 'approvals'>('overview');
  const [proposeOpen, setProposeOpen] = useState(false);
  const [revealTarget, setRevealTarget] = useState<Address | null>(null);
  const [checkingKey, setCheckingKey] = useState<string | null>(null);

  const overview = useApi<Overview>('/trishield/overview');
  const status = useApi<{ providers: Provider[]; applyEnabled: boolean; activeRules: number; note: string }>(tab === 'perimeter' && flags.network ? '/trishield/firewall/status' : null);
  const rules = useApi<{ rules: Rule[] }>(tab === 'perimeter' && flags.network ? '/trishield/firewall/rules' : null);
  const actions = useApi<FirewallAction[]>((tab === 'approvals' && flags.response) || (tab === 'perimeter' && flags.network) ? '/trishield/actions' : null);
  const network = useApi<{ data: { id: string; eventType: string; severity: string; title: string; srcIp: string | null; occurredAt: string; synthetic: boolean }[] }>(tab === 'perimeter' && flags.network ? '/trishield/network/events?limit=8' : null);
  const waf = useApi<{ data: { id: string; source: string; severity: string; title: string; occurredAt: string; synthetic: boolean }[] }>(tab === 'perimeter' && flags.network ? '/trishield/waf/events?limit=8' : null);
  const policies = useApi<Policy[]>(tab === 'perimeter' && flags.network ? '/trishield/policies' : null);
  const endpoints = useApi<EndpointPayload>(tab === 'endpoints' && flags.endpoint ? '/trishield/endpoints' : null);
  const health = useApi<HealthPayload>(tab === 'integrations' ? '/trishield/health' : null);
  const addresses = useApi<AddressPayload>(tab === 'ip' && flags.ipShield ? '/trishield/ip/addresses' : null);

  const refreshAll = () => {
    overview.refresh();
    status.refresh();
    rules.refresh();
    actions.refresh();
    policies.refresh();
    endpoints.refresh();
    addresses.refresh();
  };

  const run = async (work: () => Promise<unknown>, success: string) => {
    try {
      await work();
      toast.push('success', success);
      refreshAll();
    } catch (error) {
      toast.push('error', success.replace(/\.$/, '') + ' failed', error instanceof ApiError ? error.message : undefined);
    }
  };

  const data = overview.data;
  const layerIcon = (key: string) => key === 'perimeter' ? Globe2 : key === 'application' ? ShieldCheck : Fingerprint;

  const runCheck = async (key: string) => {
    setCheckingKey(key);
    try {
      const result = await api.post<{ result: { state: string; detail: string } }>(`/trishield/health/${key}/check`);
      toast.push(
        result.result.state === 'VERIFIED' ? 'success' : 'info',
        `${key}: ${statusLabel(result.result.state)}`,
        result.result.detail,
      );
      health.refresh();
      overview.refresh();
    } catch (error) {
      toast.push('error', `${key} check failed`, error instanceof ApiError ? error.message : undefined);
    } finally {
      setCheckingKey(null);
    }
  };

  if (!flags.enabled) {
    return (
      <>
        <PageHeader title="TriShield defense" subtitle="Disabled by server configuration." />
        <Card>
          <EmptyState
            title="TriShield is turned off"
            body="The server does not expose the TriShield API on this deployment. Remove TRISHIELD_ENABLED=false and restart to use these controls."
            icon={<ShieldOff size={18} aria-hidden="true" />}
          />
        </Card>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="TriShield defense"
        subtitle="Perimeter, application and endpoint controls with real connector health, approved firewall changes and IP privacy."
        actions={permissions.canAdmin ? (
          <>
            <Button icon={<RefreshCw size={14} aria-hidden="true" />} onClick={() => run(() => api.post('/trishield/firewall/health'), 'Firewall health checked')}>Check firewall</Button>
            <Button variant="primary" icon={<Fingerprint size={14} aria-hidden="true" />} onClick={() => run(() => api.post('/trishield/ip/discover', { includePublic: false }), 'Infrastructure addresses discovered')}>Discover IPs</Button>
          </>
        ) : undefined}
      />

      <div className="grid grid-4" style={{ marginBottom: 14 }}>
        <MetricCard label="Active firewall rules" value={data?.firewall.activeRules ?? 0} foot="Verified provider rules" icon={<Network size={12} aria-hidden="true" />} />
        <MetricCard label="Pending approvals" value={data?.pendingApprovals ?? 0} foot="Temporary firewall blocks" icon={<ShieldCheck size={12} aria-hidden="true" />} />
        <MetricCard label="Endpoint agents online" value={data?.endpoints.online ?? 0} foot={`${data?.endpoints.total ?? 0} registered`} icon={<Server size={12} aria-hidden="true" />} />
        <MetricCard label="Infrastructure addresses" value={data?.infra.total ?? 0} foot={`${data?.infra.public ?? 0} public · ${data?.infra.management ?? 0} management`} icon={<Wifi size={12} aria-hidden="true" />} />
      </div>

      {overview.loading && !data ? <Card><TableSkeleton rows={5} cols={3} /></Card> : overview.error ? <Card><ErrorState message={overview.error} onRetry={overview.refresh} /></Card> : (
        <>
          <Tabs
            id="trishield"
            label="TriShield sections"
            active={tab}
            onChange={(key) => setTab(key as typeof tab)}
            tabs={[
              { key: 'overview', label: 'Overview' },
              ...(flags.network ? [{ key: 'perimeter', label: 'Perimeter' }] : []),
              ...(flags.endpoint ? [{ key: 'endpoints', label: 'Endpoints' }] : []),
              { key: 'integrations', label: 'Integrations' },
              ...(flags.ipShield ? [{ key: 'ip', label: 'IP Shield' }] : []),
              ...(flags.response ? [{ key: 'approvals', label: 'Approvals' }] : []),
            ]}
          />

          <TabPanel id="trishield" active={tab}>
            {tab === 'overview' && data && (
              <div className="stack" style={{ gap: 14 }}>
                <div className="grid grid-3">
                  {data.layers.map((layer) => {
                    const Icon = layerIcon(layer.key);
                    return (
                      <Card key={layer.key}>
                        <div className="row" style={{ gap: 9, marginBottom: 8 }}>
                          <span style={{ width: 30, height: 30, borderRadius: 8, display: 'grid', placeItems: 'center', background: 'var(--color-panel-2)', color: 'var(--color-blue)' }}>
                            <Icon size={15} aria-hidden="true" />
                          </span>
                          <div>
                            <p style={{ fontWeight: 600 }}>{layer.name}</p>
                            <p className="tiny faint">{layer.detail}</p>
                          </div>
                          <span style={{ marginLeft: 'auto' }}><Badge tone={toneFor(layer.status)} dot>{statusLabel(layer.status)}</Badge></span>
                        </div>
                      </Card>
                    );
                  })}
                </div>

                <div className="grid grid-2">
                  <Card title="Integration health" subtitle="Configured is not the same as verified">
                    <div className="stack" style={{ gap: 10 }}>
                      {data.firewall.providers.map((provider) => (
                        <div key={provider.key} className="row" style={{ gap: 10 }}>
                          <Cloud size={14} aria-hidden="true" />
                          <div style={{ minWidth: 0, flex: 1 }}>
                            <p className="small" style={{ fontWeight: 550 }}>{provider.name}</p>
                            <p className="tiny faint">{provider.detail}</p>
                          </div>
                          <Badge tone={toneFor(provider.status)}>{statusLabel(provider.status)}</Badge>
                        </div>
                      ))}
                      {data.collectors.map((collector) => (
                        <div key={collector.id} className="row" style={{ gap: 10 }}>
                          <Radar size={14} aria-hidden="true" />
                          <div style={{ minWidth: 0, flex: 1 }}>
                            <p className="small" style={{ fontWeight: 550 }}>{collector.name} · {collector.kind}</p>
                            <p className="tiny faint">{collector.lastSeenAt ? `Last event ${timeAgo(collector.lastSeenAt)}` : 'No events received'}</p>
                          </div>
                          <Badge tone={toneFor(collector.health)}>{statusLabel(collector.health)}</Badge>
                        </div>
                      ))}
                      {!data.firewall.providers.length && !data.collectors.length && <EmptyState title="No provider configured" body="Add a firewall connector or collector token in the repository environment, then run a health check." />}
                    </div>
                  </Card>
                  <Card title="Response approvals" subtitle="Nothing high impact runs without a backend check">
                    {data.recentActions.length === 0 ? (
                      <EmptyState title="No firewall actions" body="A proposed block appears here before it can reach a provider." icon={<ShieldOff size={18} aria-hidden="true" />} />
                    ) : (
                      <div className="stack" style={{ gap: 8 }}>
                        {data.recentActions.map((action) => (
                          <div key={action.id} className="row" style={{ gap: 8 }}>
                            <Badge tone={toneFor(action.status.toUpperCase())}>{statusLabel(action.status)}</Badge>
                            <span className="mono tiny">{action.targetIp}</span>
                            <span className="tiny faint truncate-cell" style={{ flex: 1 }}>{action.reason}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </Card>
                </div>

                <InlineNotice tone="info">
                  {data.firewall.note} A connector is never labelled verified before a real health check, and simulated response actions stay in the existing labelled workflow.
                </InlineNotice>
              </div>
            )}

            {tab === 'perimeter' && (
              <div className="stack" style={{ gap: 14 }}>
                <Card title="Firewall connectors" subtitle="Credentials live in the backend environment, never in this page">
                  {status.loading && !status.data ? <TableSkeleton rows={3} cols={3} /> : status.error ? <ErrorState message={status.error} onRetry={status.refresh} /> : (
                    <div className="grid grid-2">
                      {(status.data?.providers ?? []).map((provider) => (
                        <div key={provider.key} className="card" style={{ padding: 16, boxShadow: 'none' }}>
                          <div className="row" style={{ gap: 8 }}>
                            <Cloud size={15} aria-hidden="true" />
                            <p style={{ fontWeight: 600 }}>{provider.name}</p>
                            <span style={{ marginLeft: 'auto' }}><Badge tone={toneFor(provider.status)}>{statusLabel(provider.status)}</Badge></span>
                          </div>
                          <p className="small muted" style={{ marginTop: 8 }}>{provider.detail}</p>
                          <p className="tiny faint" style={{ marginTop: 6 }}>
                            Apply {provider.applyEnabled ? 'enabled' : 'disabled'} · {provider.lastSyncAt ? `checked ${timeAgo(provider.lastSyncAt)}` : 'not checked yet'}
                          </p>
                        </div>
                      ))}
                    </div>
                  )}
                  {status.data && !status.data.applyEnabled && (
                    <InlineNotice tone="warn">Live changes are disabled. Set <span className="mono">TRISHIELD_FIREWALL_APPLY=true</span> on a host with a real connector before any rule can be applied.</InlineNotice>
                  )}
                </Card>

                <Card title="Firewall rules" subtitle="Verified active rules recorded by SecureFlow" bodyClass="">
                  {rules.loading && !rules.data ? <TableSkeleton rows={4} cols={4} /> : rules.error ? <ErrorState message={rules.error} onRetry={rules.refresh} /> : (rules.data?.rules.length ?? 0) === 0 ? (
                    <EmptyState title="No active rules" body="A rule appears here only after a provider confirms it." icon={<ShieldOff size={18} aria-hidden="true" />} />
                  ) : (
                    <div className="table-wrap" tabIndex={0} role="group" aria-label="Scrollable table">
                      <table className="data">
                        <thead><tr><th>Provider</th><th>CIDR</th><th>Action</th><th>State</th><th>Expires</th><th>Verified</th></tr></thead>
                        <tbody>
                          {rules.data?.rules.map((rule) => (
                            <tr key={rule.id}>
                              <td className="mono tiny">{rule.providerKey}</td>
                              <td className="mono tiny">{rule.cidr}</td>
                              <td><Badge tone={rule.action === 'block' ? 'critical' : 'mint'}>{rule.action}</Badge></td>
                              <td><Badge tone={toneFor(rule.state.toUpperCase())}>{rule.state}</Badge></td>
                              <td className="tiny faint">{rule.expiresAt ? formatDate(rule.expiresAt) : 'Permanent'}</td>
                              <td className="tiny faint">{rule.createdAt ? timeAgo(rule.createdAt) : '—'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </Card>

                <div className="grid grid-2">
                  <Card title="Suricata events" subtitle="Normalized EVE records. Demo fixture rows are marked simulated." bodyClass="">
                    {(network.data?.data.length ?? 0) === 0 ? <EmptyState title="No Suricata events" body="Create a collector token and send EVE JSON to the ingestion endpoint." /> : (
                      <div className="table-wrap" tabIndex={0} role="group" aria-label="Scrollable table"><table className="data"><thead><tr><th>Type</th><th>Severity</th><th>Signal</th><th>Source</th><th className="right">When</th></tr></thead><tbody>
                        {network.data?.data.map((event) => (
                          <tr key={event.id}><td className="mono tiny">{event.eventType}{event.synthetic && <> <Badge tone="neutral">simulated</Badge></>}</td><td><Badge tone={toneFor(event.severity.toUpperCase())}>{event.severity}</Badge></td><td className="truncate-cell">{event.title}</td><td className="mono tiny">{event.srcIp ?? '—'}</td><td className="right tiny faint">{timeAgo(event.occurredAt)}</td></tr>
                        ))}
                      </tbody></table></div>
                    )}
                  </Card>
                  <Card title="WAF events" subtitle="Provider-labelled application events. Demo fixture rows are marked simulated." bodyClass="">
                    {(waf.data?.data.length ?? 0) === 0 ? <EmptyState title="No WAF events" body="A WAF collector token can forward normalized block and challenge events." /> : (
                      <div className="table-wrap" tabIndex={0} role="group" aria-label="Scrollable table"><table className="data"><thead><tr><th>Provider</th><th>Severity</th><th>Signal</th><th className="right">When</th></tr></thead><tbody>
                        {waf.data?.data.map((event) => (
                          <tr key={event.id}><td className="mono tiny">{event.source}{event.synthetic && <> <Badge tone="neutral">simulated</Badge></>}</td><td><Badge tone={toneFor(event.severity.toUpperCase())}>{event.severity}</Badge></td><td className="truncate-cell">{event.title}</td><td className="right tiny faint">{timeAgo(event.occurredAt)}</td></tr>
                        ))}
                      </tbody></table></div>
                    )}
                  </Card>
                </div>

                <Card title="Automatic block policy" subtitle="Deterministic, public-source only, approval by default">
                  {policies.loading && !policies.data ? <TableSkeleton rows={2} cols={2} /> : (
                    <div className="stack" style={{ gap: 10 }}>
                      {(policies.data ?? []).map((policy) => (
                        <div key={policy.id} className="row wrap" style={{ gap: 10 }}>
                          <div style={{ flex: 1, minWidth: 220 }}>
                            <p className="small" style={{ fontWeight: 600 }}>{policy.key}</p>
                            <p className="tiny faint">Minimum severity {String(policy.config.minSeverity ?? 'high')} · {String(policy.config.durationMinutes ?? 60)} minute block · mode {policy.mode}</p>
                          </div>
                          <Badge tone={policy.enabled ? 'mint' : 'neutral'}>{policy.enabled ? 'enabled' : 'disabled'}</Badge>
                          {permissions.canAdmin && (
                            <Button size="sm" onClick={() => run(() => api.patch(`/trishield/policies/${policy.id}`, { enabled: !policy.enabled }), policy.enabled ? 'Policy disabled' : 'Policy enabled')}>
                              {policy.enabled ? 'Disable' : 'Enable'}
                            </Button>
                          )}
                        </div>
                      ))}
                      <p className="tiny faint">Auto execution additionally requires TRISHIELD_AUTO_APPLY=true and a verified connector. Without both, actions stop for approval.</p>
                    </div>
                  )}
                </Card>

                <div className="row">
                  <Button variant="primary" icon={<Plus size={14} aria-hidden="true" />} onClick={() => setProposeOpen(true)}>Propose firewall block</Button>
                </div>
              </div>
            )}

            {tab === 'endpoints' && (
              <div className="stack" style={{ gap: 14 }}>
                <div className="grid grid-3">
                  <MetricCard label="Agents online" value={endpoints.data?.agents.filter((agent) => agent.status === 'online').length ?? 0} foot={`${endpoints.data?.agents.length ?? 0} registered`} icon={<Server size={12} aria-hidden="true" />} />
                  <MetricCard label="ClamAV" value={endpoints.data?.clamav.configured ? 'Configured' : 'Not configured'} foot="Evidence scanner" icon={<ShieldCheck size={12} aria-hidden="true" />} />
                  <MetricCard label="Recent evidence" value={endpoints.data?.malwareScans.length ?? 0} foot="Scan states from the evidence register" icon={<Fingerprint size={12} aria-hidden="true" />} />
                </div>
                <Card title="Endpoint agents" subtitle="Wazuh or compatible collector" bodyClass="">
                  {endpoints.loading && !endpoints.data ? <TableSkeleton rows={4} cols={5} /> : endpoints.error ? <ErrorState message={endpoints.error} onRetry={endpoints.refresh} /> : (endpoints.data?.agents.length ?? 0) === 0 ? (
                    <EmptyState title="No endpoint agents" body="Send a Wazuh alert with a collector token to register an agent." icon={<Server size={18} aria-hidden="true" />} />
                  ) : (
                    <div className="table-wrap" tabIndex={0} role="group" aria-label="Scrollable table"><table className="data"><thead><tr><th>Agent</th><th>Host</th><th>OS</th><th>Address</th><th>Status</th><th className="right">Last seen</th></tr></thead><tbody>
                      {endpoints.data?.agents.map((agent) => (
                        <tr key={agent.id}><td className="mono tiny">{agent.agentId}</td><td>{agent.hostname || '—'}</td><td className="tiny faint">{agent.os ?? '—'}</td><td className="mono tiny">{agent.ipMasked ?? '—'}</td><td><Badge tone={toneFor(agent.status.toUpperCase())}>{agent.status}</Badge></td><td className="right tiny faint">{agent.lastSeenAt ? timeAgo(agent.lastSeenAt) : '—'}</td></tr>
                      ))}
                    </tbody></table></div>
                  )}
                </Card>
                <Card title="Evidence scan history" subtitle="ClamAV result recorded at upload" bodyClass="">
                  {(endpoints.data?.malwareScans.length ?? 0) === 0 ? <EmptyState title="No evidence yet" body="Seal evidence in Forensics to record a scan state." /> : (
                    <div className="table-wrap" tabIndex={0} role="group" aria-label="Scrollable table"><table className="data"><thead><tr><th>File</th><th>Case</th><th>Scan</th><th className="right">Created</th></tr></thead><tbody>
                      {endpoints.data?.malwareScans.map((scan) => (
                        <tr key={scan.id}><td className="truncate-cell">{scan.filename}</td><td className="mono tiny">{scan.caseRef}</td><td><Badge tone={scan.scanStatus === 'clean' ? 'mint' : scan.scanStatus === 'infected' ? 'critical' : 'neutral'}>{scan.scanStatus}</Badge></td><td className="right tiny faint">{formatDate(scan.createdAt)}</td></tr>
                      ))}
                    </tbody></table></div>
                  )}
                </Card>
              </div>
            )}

            {tab === 'integrations' && (
              <div className="stack" style={{ gap: 14 }}>
                <InlineNotice tone="info">
                  Every state comes from a recorded check or live collector telemetry. VERIFIED means the last real check succeeded. A configured variable alone is never shown as healthy.
                </InlineNotice>
                {health.loading && !health.data ? <Card><TableSkeleton rows={6} cols={3} /></Card> : health.error ? <Card><ErrorState message={health.error} onRetry={health.refresh} /></Card> : (
                  <>
                    <div className="row wrap" style={{ gap: 8 }}>
                      <Badge tone="mint">{health.data?.counts.verified ?? 0} verified</Badge>
                      <Badge tone="amber">{health.data?.counts.degraded ?? 0} degraded</Badge>
                      <Badge tone="critical">{health.data?.counts.error ?? 0} error</Badge>
                      <Badge tone="neutral">{health.data?.counts.notConfigured ?? 0} not configured</Badge>
                      <Badge tone="neutral">{health.data?.counts.unavailable ?? 0} unavailable</Badge>
                    </div>
                    <div className="grid grid-2">
                      {(health.data?.integrations ?? []).map((card) => (
                        <IntegrationSetupCard
                          key={card.key}
                          card={card}
                          canAdmin={permissions.canAdmin}
                          busy={checkingKey === card.key}
                          onCheck={() => runCheck(card.key)}
                        />
                      ))}
                    </div>
                  </>
                )}
              </div>
            )}

            {tab === 'ip' && (
              <div className="stack" style={{ gap: 14 }}>
                <InlineNotice tone="info">
                  Addresses are real values observed on this host. Normal views return a masked form; the encrypted original is available only to an administrator with a reason. No fake address is stored.
                </InlineNotice>
                <Card title="Infrastructure addresses" subtitle="Discovered from trusted local interfaces" bodyClass="">
                  {addresses.loading && !addresses.data ? <TableSkeleton rows={5} cols={6} /> : addresses.error ? <ErrorState message={addresses.error} onRetry={addresses.refresh} /> : (addresses.data?.addresses.length ?? 0) === 0 ? (
                    <EmptyState title="No addresses discovered" body="Run Discover IPs to read the host interfaces." icon={<Wifi size={18} aria-hidden="true" />} />
                  ) : (
                    <div className="table-wrap" tabIndex={0} role="group" aria-label="Scrollable table"><table className="data"><thead><tr><th>Address</th><th>Type</th><th>Interface</th><th>Scope</th><th>Fingerprint</th><th>Vault</th><th></th></tr></thead><tbody>
                      {addresses.data?.addresses.map((address) => (
                        <tr key={address.id}>
                          <td className="mono tiny">{address.masked}</td>
                          <td className="tiny">{address.family}</td>
                          <td className="tiny faint">{address.interface || '—'}</td>
                          <td><Badge tone={address.isManagement ? 'amber' : address.scope === 'public' ? 'info' : 'neutral'}>{address.isManagement ? 'management' : address.scope}</Badge></td>
                          <td className="mono tiny">{address.fingerprint ? address.fingerprint.slice(0, 18) + '…' : 'key not configured'}</td>
                          <td className="tiny faint">{address.vaulted ? 'sealed' : 'not configured'}</td>
                          <td className="right">{permissions.canAdmin && address.vaulted ? <Button size="sm" onClick={() => setRevealTarget(address)}>Reveal</Button> : null}</td>
                        </tr>
                      ))}
                    </tbody></table></div>
                  )}
                </Card>
                <Card title="Origin protection" subtitle="Configuration evidence, not a claim that the origin is hidden">
                  <KeyValue items={[
                    { label: 'Reverse proxy', value: String(addresses.data?.origin.reverseProxyConfigured ?? false) },
                    { label: 'Trusted proxy', value: String(addresses.data?.origin.trustedProxy ?? false) },
                    { label: 'Public IP discovery', value: String(addresses.data?.origin.publicIpDiscoveryConfigured ?? false) },
                    { label: 'Origin hostname check', value: String(addresses.data?.origin.originHostnameConfigured ?? false) },
                  ]} />
                </Card>
              </div>
            )}

            {tab === 'approvals' && (
              <Card title="Firewall actions" subtitle="Proposed, approved and verified changes" bodyClass="">
                {actions.loading && !actions.data ? <TableSkeleton rows={5} cols={6} /> : actions.error ? <ErrorState message={actions.error} onRetry={actions.refresh} /> : (actions.data?.length ?? 0) === 0 ? (
                  <EmptyState title="No firewall actions" body="A proposed block appears here first. Nothing is applied without authorisation." icon={<ShieldCheck size={18} aria-hidden="true" />} />
                ) : (
                  <div className="table-wrap" tabIndex={0} role="group" aria-label="Scrollable table"><table className="data"><thead><tr><th>Target</th><th>Provider</th><th>Risk</th><th>Status</th><th>Reason</th><th className="right">Created</th><th></th></tr></thead><tbody>
                    {actions.data?.map((action) => (
                      <tr key={action.id}>
                        <td className="mono tiny">{action.targetIp}</td>
                        <td className="tiny">{action.providerKey}</td>
                        <td><Badge tone={action.riskClass === 'high' ? 'critical' : 'amber'}>{action.riskClass}</Badge></td>
                        <td><Badge tone={toneFor(action.status.toUpperCase())}>{statusLabel(action.status)}</Badge></td>
                        <td className="tiny faint truncate-cell" style={{ maxWidth: 260 }}>{action.reason}</td>
                        <td className="right tiny faint">{timeAgo(action.createdAt)}</td>
                        <td className="right">
                          <div className="row" style={{ gap: 4, justifyContent: 'flex-end' }}>
                            {permissions.canAdmin && action.status === 'awaiting_approval' && <Button size="sm" onClick={() => run(() => api.post(`/trishield/actions/${action.id}/approve`), 'Action approved')}>Approve</Button>}
                            {permissions.canAdmin && action.status === 'awaiting_approval' && <Button size="sm" variant="ghost" onClick={() => run(() => api.post(`/trishield/actions/${action.id}/reject`), 'Action rejected')}>Reject</Button>}
                            {permissions.canAdmin && action.status === 'approved' && <Button size="sm" variant="primary" onClick={() => run(() => api.post(`/trishield/actions/${action.id}/execute`), 'Firewall action executed')}>Execute</Button>}
                            {permissions.canAdmin && action.status === 'succeeded' && <Button size="sm" variant="ghost" onClick={() => run(() => api.post(`/trishield/actions/${action.id}/rollback`), 'Firewall action rolled back')}>Rollback</Button>}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody></table></div>
                )}
              </Card>
            )}
          </TabPanel>
        </>
      )}

      <ProposeActionModal
        open={proposeOpen}
        providers={status.data?.providers ?? data?.firewall.providers ?? []}
        onClose={() => setProposeOpen(false)}
        onCreated={() => { setProposeOpen(false); refreshAll(); }}
      />
      <RevealAddressModal
        target={revealTarget}
        onClose={() => setRevealTarget(null)}
      />
    </>
  );
}

function IntegrationSetupCard({ card, canAdmin, busy, onCheck }: {
  card: IntegrationCard; canAdmin: boolean; busy: boolean; onCheck: () => void;
}) {
  const configured = card.missing.length === 0;
  const connected = ['CONNECTED', 'VERIFIED', 'DEGRADED'].includes(card.state) || Boolean(card.lastSuccessAt);
  const verified = card.state === 'VERIFIED';
  const rows = [
    { label: 'Configuration', ok: configured, text: configured ? 'Required settings present' : `Missing ${card.missing.join(', ')}` },
    { label: 'Connection', ok: connected, text: connected ? 'A check reached the provider' : 'No successful connection recorded' },
    { label: 'Verification', ok: verified, text: verified ? 'The last check confirmed functionality' : 'Functionality not verified yet' },
  ];
  return (
    <Card
      title={card.name}
      subtitle={`${card.layer} layer · ${card.category}`}
      actions={<Badge tone={toneFor(card.state)} dot>{statusLabel(card.state)}</Badge>}
      footer={(
        <div className="row" style={{ gap: 8 }}>
          <Button size="sm" onClick={onCheck} loading={busy} disabled={!canAdmin} icon={<RefreshCw size={13} aria-hidden="true" />}>
            Test connection
          </Button>
          <span className="tiny faint">{canAdmin ? 'Runs a real check and records it' : 'Administrator only'}</span>
        </div>
      )}
    >
      <div className="stack" style={{ gap: 10 }}>
        {rows.map((row) => (
          <div key={row.label} className="row" style={{ gap: 8, alignItems: 'flex-start' }}>
            {row.ok
              ? <CheckCircle2 size={14} style={{ color: 'var(--color-mint)', flexShrink: 0, marginTop: 2 }} aria-hidden="true" />
              : <XCircle size={14} style={{ color: 'var(--color-faint)', flexShrink: 0, marginTop: 2 }} aria-hidden="true" />}
            <div style={{ minWidth: 0 }}>
              <p className="tiny" style={{ fontWeight: 600 }}>{row.label}</p>
              <p className="tiny faint">{row.text}</p>
            </div>
          </div>
        ))}
        {card.detail && <p className="small muted">{card.detail}</p>}
        <div className="row wrap tiny faint" style={{ gap: 12 }}>
          <span>Last check {card.lastCheckedAt ? timeAgo(card.lastCheckedAt) : 'never'}</span>
          {card.latencyMs !== null && <span>{card.latencyMs} ms</span>}
          {card.version && <span>{card.version}</span>}
        </div>
        {card.missing.length > 0 && (
          <InlineNotice tone="warn">
            <span className="row" style={{ gap: 6 }}>
              <AlertTriangle size={13} aria-hidden="true" /> {card.missing.join(' · ')}
            </span>
          </InlineNotice>
        )}
        <p className="tiny muted">Next: {card.nextAction}</p>
        <details className="setup-details">
          <summary className="small">Setup steps</summary>
          <div className="stack" style={{ gap: 8, marginTop: 8 }}>
            {(['windows', 'linux', 'cloud'] as const).map((platform) => (
              <div key={platform}>
                <p className="tiny" style={{ fontWeight: 600 }}>
                  {platform === 'windows' ? 'Windows' : platform === 'linux' ? 'Linux' : 'Cloud'}
                </p>
                <ol className="tiny faint" style={{ paddingLeft: 16, margin: '4px 0 0' }}>
                  {card.setup[platform].map((line) => <li key={line}>{line}</li>)}
                </ol>
              </div>
            ))}
          </div>
        </details>
      </div>
    </Card>
  );
}

function ProposeActionModal({ open, providers, onClose, onCreated }: {
  open: boolean; providers: Provider[]; onClose: () => void; onCreated: () => void;
}) {
  const toast = useToast();
  const [form, setForm] = useState({ providerKey: 'nftables', targetIp: '', reason: '', minutes: '60', permanent: false });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setBusy(true); setError(null);
    try {
      await api.post('/trishield/actions', {
        providerKey: form.providerKey, type: 'block_ip', targetIp: form.targetIp.trim(),
        reason: form.reason.trim(), expiresMinutes: Number(form.minutes) || 60, permanent: form.permanent,
      });
      toast.push('success', 'Firewall action proposed');
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not propose the action');
    } finally { setBusy(false); }
  };

  return (
    <Modal open={open} onClose={onClose} title="Propose a firewall block" subtitle="Only a public address can be blocked. Management addresses are refused."
      footer={<><Button variant="ghost" onClick={onClose} type="button">Cancel</Button><Button variant="primary" onClick={submit} loading={busy} type="button" disabled={!form.targetIp.trim() || form.reason.trim().length < 6}>Propose</Button></>}>
      {error && <div className="error-box" role="alert">{error}</div>}
      <Field label="Provider" htmlFor="tri-provider">
        <select id="tri-provider" className="select" value={form.providerKey} onChange={(e) => setForm({ ...form, providerKey: e.target.value })}>
          {providers.map((provider) => <option key={provider.key} value={provider.key}>{provider.name} · {provider.status}</option>)}
        </select>
      </Field>
      <Field label="Address" htmlFor="tri-ip" hint="IPv4 or IPv6. Private, loopback and management addresses are refused.">
        <input id="tri-ip" className="input" value={form.targetIp} onChange={(e) => setForm({ ...form, targetIp: e.target.value })} placeholder="203.0.113.10" />
      </Field>
      <Field label="Reason" htmlFor="tri-reason" hint="Recorded in the audit trail.">
        <textarea id="tri-reason" className="textarea" value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} placeholder="Credential stuffing source confirmed by WAF and authentication telemetry." />
      </Field>
      <div className="grid grid-2">
        <Field label="Duration (minutes)" htmlFor="tri-minutes">
          <input id="tri-minutes" className="input" type="number" min={1} max={10080} value={form.minutes} disabled={form.permanent} onChange={(e) => setForm({ ...form, minutes: e.target.value })} />
        </Field>
        <Field label="Permanent" htmlFor="tri-permanent" hint="Administrator and recent authentication required.">
          <label className="row small" htmlFor="tri-permanent" style={{ gap: 8 }}>
            <input id="tri-permanent" type="checkbox" checked={form.permanent} onChange={(e) => setForm({ ...form, permanent: e.target.checked })} />
            No expiry
          </label>
        </Field>
      </div>
      <p className="tiny faint">A proposed action is not a firewall change. It must be approved and then executed, and the provider answer is verified before success is recorded.</p>
    </Modal>
  );
}

function RevealAddressModal({ target, onClose }: { target: Address | null; onClose: () => void }) {
  const toast = useToast();
  const [reason, setReason] = useState('');
  const [value, setValue] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const reveal = async () => {
    if (!target) return;
    setBusy(true); setError(null);
    try {
      const result = await api.post<{ address: string; keyVersion: string }>(`/trishield/ip/${target.id}/reveal`, { reason });
      setValue(result.address);
      toast.push('success', 'Address revealed and audited');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not reveal the address');
    } finally { setBusy(false); }
  };

  const close = () => { setValue(null); setReason(''); setError(null); onClose(); };

  return (
    <Modal open={Boolean(target)} onClose={close} title="Reveal infrastructure address" subtitle="This action is restricted and audited."
      footer={<><Button variant="ghost" onClick={close} type="button">Close</Button>{!value && <Button variant="primary" onClick={reveal} loading={busy} type="button" disabled={reason.trim().length < 6}>Reveal</Button>}</>}>
      {error && <div className="error-box" role="alert">{error}</div>}
      {value ? (
        <div>
          <p className="tiny faint">Original address</p>
          <pre className="code-block" tabIndex={0}>{value}</pre>
          <p className="tiny faint" style={{ marginTop: 8 }}>The reveal was recorded in the audit log with your user and reason.</p>
        </div>
      ) : (
        <>
          <p className="small muted">Address {target?.masked} is sealed in the IP vault. Provide a reason for the access record.</p>
          <Field label="Reason" htmlFor="reveal-reason">
            <textarea id="reveal-reason" className="textarea" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Investigating a firewall change against the origin host." />
          </Field>
        </>
      )}
    </Modal>
  );
}
