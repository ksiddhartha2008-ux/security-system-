export type SiteStatus = 'pending_verification' | 'verified' | 'lapsed' | 'expired' | 'deleted';
export type ConnectionState = 'never_connected' | 'connected' | 'silent' | 'suspended';

export type Connection = { state: ConnectionState; label: string; reason: string | null };
export type HealthWarning = { code: string; label: string; detail: string };

export type Website = {
  id: string;
  displayName: string;
  inputUrl: string;
  hostname: string;
  hostnameUnicode: string;
  scheme: string;
  scope: 'host' | 'domain';
  registrableDomain: string;
  criticality: number;
  criticalityLabel: string;
  status: SiteStatus;
  verifiedAt: string | null;
  lastVerificationOkAt: string | null;
  verificationFailingSince: string | null;
  lastEventAt: string | null;
  lastHeartbeatAt: string | null;
  connectedAt: string | null;
  assetId: string | null;
  riskScore: number | null;
  connection: Connection;
  healthWarnings: HealthWarning[];
  openIncidents?: number;
  keysActive?: number;
  createdAt: string;
};

export type Verification = {
  id: string;
  status: 'pending' | 'verified' | 'expired' | 'superseded' | 'conflict';
  method: string;
  recordName: string;
  lastResult: 'ok' | 'not_found' | 'mismatch' | 'resolver_error' | null;
  lastCheckedAt: string | null;
  attemptCount: number;
  verifiedAt: string | null;
  expiresAt: string;
};

export type DnsInstructions = {
  type: string;
  relativeName: string;
  fullName: string;
  value: string;
  ttl: number;
  expiresAt: string;
  expiresInSeconds: number;
  sentence: string;
};

export type Notification = {
  id: string;
  kind: string;
  priority: string;
  status: 'sent' | 'suppressed' | 'failed';
  suppressionReason: string | null;
  title: string;
  body: string;
  createdAt: string;
};

export type WebsiteDetail = Website & {
  verification: Verification | null;
  dns: DnsInstructions | null;
  sensitivePaths: string[];
  stats: {
    events24h: number;
    events7d: number;
    detections: number;
    incidents: number;
    topSources: { ip: string; count: number }[];
    detectionsByRule: { ruleKey: string; count: number }[];
  };
  notifications: Notification[];
  installSnippet: string | null;
  heartbeatSeconds: number;
};

export type ApiKeyRow = {
  id: string;
  keyId: string;
  last4: string;
  label: string;
  scopes: string;
  status: 'active' | 'revoked' | 'expired';
  createdAt: string;
  expiresAt: string | null;
  lastUsedAt: string | null;
  revokedAt: string | null;
};

export type CreatedKey = ApiKeyRow & { apiKey: string };

export type WebsiteEvent = {
  id: string;
  type: string;
  eventType: string;
  title: string;
  srcIp: string | null;
  actor: string | null;
  path: string | null;
  method: string | null;
  status: number | null;
  userAgent: string | null;
  attributes: Record<string, string | number | boolean>;
  ipClass: string | null;
  trustLevel: string;
  occurredAt: string;
};

export type WebsiteDetection = {
  id: string;
  title: string;
  description: string;
  severity: string;
  riskScore: number;
  confidence: number;
  status: string;
  ruleKey: string | null;
  factors: { label: string; weight: number; detail: string }[];
  observed: Record<string, unknown>;
  detectedAt: string;
  incidentId: string | null;
};

export type WebsiteIncident = {
  id: string;
  ref: string;
  title: string;
  severity: string;
  priority: string;
  status: string;
  detectedAt: string;
};

export const STATUS_LABEL: Record<SiteStatus, string> = {
  pending_verification: 'Pending verification',
  verified: 'Verified',
  lapsed: 'Lapsed',
  expired: 'Expired',
  deleted: 'Deleted',
};

export const SITE_STATUS_TONE: Record<SiteStatus, string> = {
  pending_verification: 'amber',
  verified: 'mint',
  lapsed: 'critical',
  expired: 'high',
  deleted: 'neutral',
};

export const CONNECTION_TONE: Record<ConnectionState, string> = {
  connected: 'mint',
  never_connected: 'low',
  silent: 'high',
  suspended: 'neutral',
};

export const VERIFY_MESSAGE: Record<string, string> = {
  not_found: 'We could not find the record yet. DNS changes can take time to spread.',
  mismatch: 'TXT records exist at that name but none match the value above.',
  resolver_error: 'Our DNS lookup had a problem. This is not your fault. We will retry.',
  ok: 'The record matches. Ownership is verified.',
};

export const isTestDomain = (hostname: string) =>
  hostname === 'example.com' || hostname === 'example.net' || hostname === 'example.org'
  || /\.(test|example|invalid|localhost)$/.test(hostname);

export function remaining(expiresAt: string): string {
  const ms = new Date(expiresAt).getTime() - Date.now();
  if (!Number.isFinite(ms) || ms <= 0) return 'expired';
  const days = Math.floor(ms / 86400000);
  const hours = Math.floor((ms % 86400000) / 3600000);
  if (days > 0) return `${days} day${days === 1 ? '' : 's'} ${hours} hour${hours === 1 ? '' : 's'}`;
  const minutes = Math.floor((ms % 3600000) / 60000);
  return `${hours} hour${hours === 1 ? '' : 's'} ${minutes} minute${minutes === 1 ? '' : 's'}`;
}
