import { useId, useMemo } from 'react';

type Series = { key: string; label: string; color: string };

/** Line and area chart with a shared scale, grid lines and an accessible summary. */
export function TrendChart({ data, series, height = 210, valueSuffix = '' }: {
  data: Record<string, number | string>[];
  series: Series[];
  height?: number;
  valueSuffix?: string;
}) {
  const id = useId().replace(/:/g, '');
  const width = 720;
  const padding = { top: 14, right: 12, bottom: 24, left: 34 };
  const innerW = width - padding.left - padding.right;
  const innerH = height - padding.top - padding.bottom;

  const max = useMemo(() => {
    let peak = 0;
    for (const row of data) for (const s of series) peak = Math.max(peak, Number(row[s.key] ?? 0));
    if (peak <= 0) return 5;
    // Choose a round step so the five grid labels are readable numbers.
    const raw = peak / 5;
    const magnitude = 10 ** Math.floor(Math.log10(raw));
    const step = [1, 2, 2.5, 5, 10].map((m) => m * magnitude).find((candidate) => candidate >= raw) ?? 10 * magnitude;
    return step * 5;
  }, [data, series]);

  const x = (i: number) => padding.left + (data.length <= 1 ? innerW / 2 : (i / (data.length - 1)) * innerW);
  const y = (value: number) => padding.top + innerH - (Number(value) / max) * innerH;
  const gridLines = [0, 0.2, 0.4, 0.6, 0.8, 1];

  const summary = series.map((s) => {
    const values = data.map((d) => Number(d[s.key] ?? 0));
    const total = values.reduce((a, b) => a + b, 0);
    return `${s.label} total ${total}`;
  }).join(', ');

  return (
    <div>
      <div className="row" style={{ gap: 14, marginBottom: 6, flexWrap: 'wrap' }}>
        {series.map((s) => (
          <span key={s.key} className="tiny muted row" style={{ gap: 6 }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: s.color, display: 'inline-block' }} aria-hidden="true" />
            {s.label}
          </span>
        ))}
      </div>
      <svg viewBox={`0 0 ${width} ${height}`} width="100%" height={height} role="img" aria-label={`Trend chart. ${summary}`} preserveAspectRatio="none">
        {gridLines.map((g) => (
          <g key={g}>
            <line x1={padding.left} x2={width - padding.right} y1={padding.top + innerH * g} y2={padding.top + innerH * g}
              stroke="var(--color-chart-grid)" strokeWidth="1" strokeDasharray={g === 1 ? '0' : '3 4'} />
            <text x={padding.left - 6} y={padding.top + innerH * g + 3} textAnchor="end" fontSize="9" fill="var(--color-faint)">
              {Math.round(max * (1 - g))}
            </text>
          </g>
        ))}
        {series.map((s) => {
          const points = data.map((row, i) => [x(i), y(Number(row[s.key] ?? 0))] as const);
          if (points.length === 0) return null;
          const line = points.map(([px, py], i) => `${i === 0 ? 'M' : 'L'}${px.toFixed(1)},${py.toFixed(1)}`).join(' ');
          const area = `${line} L${points[points.length - 1][0].toFixed(1)},${padding.top + innerH} L${points[0][0].toFixed(1)},${padding.top + innerH} Z`;
          return (
            <g key={s.key}>
              <defs>
                <linearGradient id={`${id}-${s.key}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" style={{ stopColor: s.color }} stopOpacity="0.26" />
                  <stop offset="100%" style={{ stopColor: s.color }} stopOpacity="0.01" />
                </linearGradient>
              </defs>
              <path d={area} fill={`url(#${id}-${s.key})`} />
              <path d={line} fill="none" style={{ stroke: s.color }} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
              {points.length <= 20 && points.map(([px, py], i) => (
                <circle key={i} cx={px} cy={py} r="2.4" style={{ fill: "var(--color-chart-point)", stroke: s.color }} strokeWidth="1.6" />
              ))}
            </g>
          );
        })}
        {data.map((row, i) => {
          const step = Math.max(1, Math.ceil(data.length / 7));
          if (i % step !== 0 && i !== data.length - 1) return null;
          return (
            <text key={i} x={x(i)} y={height - 6} textAnchor="middle" fontSize="9" fill="var(--color-faint)">
              {String(row.day ?? row.label ?? '').slice(5)}
            </text>
          );
        })}
      </svg>
      {valueSuffix && <p className="tiny faint" style={{ marginTop: 2 }}>{valueSuffix}</p>}
    </div>
  );
}

export function BarChart({ data, color = 'var(--color-mint)', height = 190, format }: {
  data: { label: string; value: number }[];
  color?: string;
  height?: number;
  format?: (value: number) => string;
}) {
  const width = 560;
  const padding = { top: 12, right: 8, bottom: 26, left: 8 };
  const innerW = width - padding.left - padding.right;
  const innerH = height - padding.top - padding.bottom;
  const max = Math.max(1, ...data.map((d) => d.value));
  const barWidth = data.length ? Math.min(38, innerW / data.length - 8) : 10;

  return (
    <svg viewBox={`0 0 ${width} ${height}`} width="100%" height={height} role="img" aria-label={data.map((d) => `${d.label}: ${d.value}`).join(', ')} preserveAspectRatio="none">
      {data.map((d, i) => {
        const slot = innerW / Math.max(data.length, 1);
        const cx = padding.left + slot * i + slot / 2;
        const barHeight = Math.max(2, (d.value / max) * innerH);
        return (
          <g key={`${d.label}-${i}`}>
            <rect x={cx - barWidth / 2} y={padding.top + innerH - barHeight} width={barWidth} height={barHeight} rx="3" style={{ fill: color }} opacity={0.9} />
            <text x={cx} y={padding.top + innerH - barHeight - 5} textAnchor="middle" fontSize="9.5" fill="var(--color-muted)">
              {format ? format(d.value) : d.value}
            </text>
            <text x={cx} y={height - 8} textAnchor="middle" fontSize="9" fill="var(--color-faint)">{d.label}</text>
          </g>
        );
      })}
    </svg>
  );
}

export function Donut({ segments, centerValue, centerLabel, size = 168 }: {
  segments: { label: string; value: number; color: string }[];
  centerValue: string | number;
  centerLabel: string;
  size?: number;
}) {
  const total = Math.max(1, segments.reduce((sum, s) => sum + s.value, 0));
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;
  return (
    <div className="row" style={{ gap: 16, flexWrap: 'wrap' }}>
      <svg width={size} height={size} viewBox="0 0 140 140" role="img" aria-label={segments.map((s) => `${s.label}: ${s.value}`).join(', ')}>
        <circle cx="70" cy="70" r={radius} fill="none" stroke="var(--color-callout)" strokeWidth="14" />
        {segments.filter((s) => s.value > 0).map((s) => {
          const length = (s.value / total) * circumference;
          const dash = `${length} ${circumference - length}`;
          const el = (
            <circle key={s.label} cx="70" cy="70" r={radius} fill="none" style={{ stroke: s.color }} strokeWidth="14"
              strokeDasharray={dash} strokeDashoffset={-offset} transform="rotate(-90 70 70)" strokeLinecap="butt" />
          );
          offset += length;
          return el;
        })}
        <text x="70" y="68" textAnchor="middle" fontSize="20" fontWeight="650" fill="var(--color-ink-strong)">{centerValue}</text>
        <text x="70" y="84" textAnchor="middle" fontSize="9" fill="var(--color-faint)">{centerLabel}</text>
      </svg>
      <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'grid', gap: 7, flex: 1, minWidth: 140 }}>
        {segments.map((s) => (
          <li key={s.label} className="row" style={{ gap: 8, fontSize: 12 }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: s.color, display: 'inline-block' }} aria-hidden="true" />
            <span className="muted" style={{ textTransform: 'capitalize' }}>{s.label}</span>
            <span style={{ marginLeft: 'auto', fontVariantNumeric: 'tabular-nums' }}>{s.value}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function RankBars({ items, color = 'var(--color-info-text)', maxValue }: {
  items: { label: string; value: number; hint?: string }[];
  color?: string;
  maxValue?: number;
}) {
  const max = Math.max(1, maxValue ?? Math.max(...items.map((i) => i.value), 1));
  return (
    <div className="stack" style={{ gap: 10 }}>
      {items.map((item) => (
        <div className="bar-row" key={item.label}>
          <span className="truncate" title={item.label} style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.label}</span>
          <div className="bar-track" aria-hidden="true">
            <div className="bar-fill" style={{ width: `${Math.min(100, (item.value / max) * 100)}%`, background: color }} />
          </div>
          <span className="right mono" style={{ color: 'var(--color-muted)' }}>{item.hint ?? item.value}</span>
        </div>
      ))}
      {items.length === 0 && <p className="small faint">No data in this window.</p>}
    </div>
  );
}

export function Sparkline({ values, color = 'var(--color-mint)', width = 86, height = 26 }: { values: number[]; color?: string; width?: number; height?: number }) {
  if (!values.length) return null;
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const span = Math.max(max - min, 1);
  const points = values.map((v, i) => {
    const x = (i / Math.max(values.length - 1, 1)) * width;
    const y = height - ((v - min) / span) * (height - 4) - 2;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} aria-hidden="true" style={{ overflow: 'visible' }}>
      <polyline points={points} fill="none" style={{ stroke: color }} strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" opacity="0.9" />
    </svg>
  );
}

export function RiskGauge({ score, size = 132 }: { score?: number | null; size?: number }) {
  const value = Math.max(0, Math.min(100, score ?? 0));
  const radius = 48;
  const circumference = Math.PI * radius;
  const dash = (value / 100) * circumference;
  const color = value >= 85 ? 'var(--color-red)' : value >= 70 ? 'var(--color-orange)' : value >= 40 ? 'var(--color-amber)' : 'var(--color-mint)';
  return (
    <svg width={size} height={size * 0.62} viewBox="0 0 120 74" role="img" aria-label={`Risk score ${score ?? 0} out of 100`}>
      <path d="M12 62 A48 48 0 0 1 108 62" fill="none" stroke="var(--color-callout)" strokeWidth="9" strokeLinecap="round" />
      <path d="M12 62 A48 48 0 0 1 108 62" fill="none" style={{ stroke: color }} strokeWidth="9" strokeLinecap="round"
        strokeDasharray={`${dash} ${circumference}`} />
      <text x="60" y="56" textAnchor="middle" fontSize="22" fontWeight="650" fill="var(--color-ink-strong)">{score ?? '—'}</text>
      <text x="60" y="68" textAnchor="middle" fontSize="8" fill="var(--color-faint)">RISK / 100</text>
    </svg>
  );
}
