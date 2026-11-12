import type { ReactNode } from 'react';
import { Card } from '@astryxdesign/core/Card';
import { Text } from '@astryxdesign/core/Text';

/**
 * Astryx-powered metric card. The application keeps one metric shape across the
 * dashboard while the visual treatment comes from the design system.
 */
export function MetricCard({ label, value, foot, icon, spark }: {
  label: string;
  value: ReactNode;
  foot?: ReactNode;
  icon?: ReactNode;
  spark?: ReactNode;
}) {
  return (
    <Card padding={4} className="metric-card">
      <div className="kpi-label">{icon}{label}</div>
      <Text type="display-1" weight="semibold" hasTabularNumbers className="kpi-value">{value}</Text>
      {foot && <Text as="div" type="supporting" className="kpi-foot">{foot}</Text>}
      {spark && <div className="kpi-spark">{spark}</div>}
    </Card>
  );
}
