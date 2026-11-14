import type { ReactNode } from 'react';
import { Card } from '@astryxdesign/core/Card';
import { Text } from '@astryxdesign/core/Text';
import { AnimatedMetric } from './motion';

/**
 * Astryx-powered metric card. The application keeps one metric shape across the
 * dashboard while the visual treatment comes from the design system.
 */
export function MetricCard({ label, value, foot, icon, spark, decimals = 0 }: {
  label: string;
  value: ReactNode;
  foot?: ReactNode;
  icon?: ReactNode;
  spark?: ReactNode;
  decimals?: number;
}) {
  const shown = typeof value === 'number' ? <AnimatedMetric value={value} decimals={decimals} /> : value;
  return (
    <Card padding={4} className={`metric-card${spark ? ' has-spark' : ''}`}>
      <div className="kpi-label">{icon}{label}</div>
      <Text type="display-1" weight="semibold" hasTabularNumbers className="kpi-value">{shown}</Text>
      {foot && <Text as="div" type="supporting" className="kpi-foot">{foot}</Text>}
      {spark && <div className="kpi-spark">{spark}</div>}
    </Card>
  );
}
