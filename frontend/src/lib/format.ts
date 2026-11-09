export function formatDate(value?: string | null, withTime = true): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  const options: Intl.DateTimeFormatOptions = withTime
    ? { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' }
    : { year: 'numeric', month: 'short', day: '2-digit' };
  return new Intl.DateTimeFormat('en-GB', options).format(date);
}

export function timeAgo(value?: string | null): string {
  if (!value) return '—';
  const date = new Date(value).getTime();
  if (Number.isNaN(date)) return '—';
  const seconds = Math.round((Date.now() - date) / 1000);
  const abs = Math.abs(seconds);
  if (abs < 45) return 'just now';
  const units: [number, Intl.RelativeTimeFormatUnit][] = [
    [60, 'minute'], [3600, 'hour'], [86400, 'day'], [604800, 'week'], [2592000, 'month'], [31536000, 'year'],
  ];
  const formatter = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });
  if (abs < 3600) return formatter.format(-Math.round(seconds / 60), 'minute');
  if (abs < 86400) return formatter.format(-Math.round(seconds / 3600), 'hour');
  if (abs < 604800) return formatter.format(-Math.round(seconds / 86400), 'day');
  if (abs < 2592000) return formatter.format(-Math.round(seconds / 604800), 'week');
  if (abs < 31536000) return formatter.format(-Math.round(seconds / 2592000), 'month');
  return formatter.format(-Math.round(seconds / 31536000), 'year');
}

export function formatNumber(value?: number | null): string {
  if (value === null || value === undefined || Number.isNaN(value)) return '—';
  return new Intl.NumberFormat('en-US').format(value);
}

export function formatBytes(bytes?: number | null): string {
  if (bytes === null || bytes === undefined || Number.isNaN(bytes)) return '—';
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = bytes / 1024;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) { value /= 1024; index += 1; }
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[index]}`;
}

export function titleCase(value?: string | null): string {
  if (!value) return '—';
  return value
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[_-]/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

export type Tone = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'neutral' | 'mint' | 'amber' | 'purple';

export function severityTone(severity?: string | null): Tone {
  switch ((severity ?? '').toLowerCase()) {
    case 'critical': return 'critical';
    case 'high': return 'high';
    case 'medium': return 'medium';
    case 'low': return 'low';
    case 'info': return 'info';
    default: return 'neutral';
  }
}

export function statusTone(status?: string | null): Tone {
  switch ((status ?? '').toLowerCase()) {
    case 'open': case 'new': return 'medium';
    case 'active': return 'mint';
    case 'investigating': case 'preparing': case 'running': case 'queued': return 'low';
    case 'contained': case 'in_progress': return 'amber';
    case 'resolved': case 'completed': case 'confirmed': case 'connected': case 'ready': return 'mint';
    case 'closed': case 'reconciled': case 'remediated': return 'neutral';
    case 'failed': case 'error': case 'cancelled': return 'critical';
    case 'false_positive': return 'neutral';
    case 'pending_approval': return 'amber';
    default: return 'neutral';
  }
}

export function riskTone(score?: number | null): Tone {
  if (score === null || score === undefined) return 'neutral';
  if (score >= 85) return 'critical';
  if (score >= 70) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

export const ROLE_LABEL: Record<string, string> = { admin: 'Admin', analyst: 'Security analyst', viewer: 'Viewer' };

export function initials(name?: string | null): string {
  if (!name) return '?';
  return name.split(/\s+/).slice(0, 2).map((p) => p[0]?.toUpperCase() ?? '').join('') || '?';
}

export function pct(part?: number | null, total?: number | null): number {
  if (!total) return 0;
  return Math.round(((part ?? 0) / total) * 100);
}
