import { useEffect, useRef, useState } from 'react';
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom';
import {
  Activity, Blocks, BrainCircuit, ChevronDown, Database, FileText, Fingerprint,
  FlaskConical, Globe2, LayoutDashboard, LogOut, Network, Radar, Server,
  Settings, ShieldAlert, ShieldCheck, Siren, Users, Search,
} from 'lucide-react';
import { AppShell } from '@astryxdesign/core/AppShell';
import { TopNav, TopNavHeading } from '@astryxdesign/core/TopNav';
import { SideNav, SideNavItem, SideNavSection } from '@astryxdesign/core/SideNav';
import { Button } from '@astryxdesign/core/Button';
import { Heading } from '@astryxdesign/core/Heading';
import { Text } from '@astryxdesign/core/Text';
import { useAuth } from '../lib/auth';
import { useApi, useEventStream } from '../lib/hooks';
import { initials, ROLE_LABEL } from '../lib/format';

const NAV = [
  {
    label: 'Operations',
    items: [
      { to: '/overview', label: 'Overview', icon: LayoutDashboard },
      { to: '/monitoring', label: 'Live monitoring', icon: Activity },
      { to: '/threat-intel', label: 'Threat intelligence', icon: Globe2 },
      { to: '/assets', label: 'Assets', icon: Server },
      { to: '/websites', label: 'Websites', icon: Globe2 },
    ],
  },
  {
    label: 'Response',
    items: [
      { to: '/incidents', label: 'Incidents', icon: Siren, badge: 'incidents' },
      { to: '/investigations', label: 'Investigations', icon: Search },
      { to: '/detections', label: 'Detections', icon: Radar, badge: 'detections' },
      { to: '/phishing', label: 'Phishing scanner', icon: ShieldAlert },
    ],
  },
  {
    label: 'Exposure',
    items: [
      { to: '/vulnerabilities', label: 'Vulnerabilities', icon: ShieldCheck },
      { to: '/network', label: 'Network', icon: Network },
      { to: '/forensics', label: 'Forensics', icon: Fingerprint },
    ],
  },
  {
    label: 'Programme',
    items: [
      { to: '/automation', label: 'Automation', icon: Blocks },
      { to: '/reports', label: 'Reports', icon: FileText },
      { to: '/simulations', label: 'Simulation lab', icon: FlaskConical },
    ],
  },
  {
    label: 'Workspace',
    items: [
      { to: '/users', label: 'People', icon: Users },
      { to: '/settings', label: 'Settings', icon: Settings },
      { to: '/demo-data', label: 'Demo data', icon: Database },
    ],
  },
];

const TITLES: Record<string, string> = {
  '/overview': 'Security overview',
  '/monitoring': 'Live monitoring',
  '/threat-intel': 'Threat intelligence',
  '/assets': 'Asset inventory',
  '/websites': 'Websites',
  '/incidents': 'Incident response',
  '/investigations': 'Investigations',
  '/detections': 'Detections',
  '/phishing': 'Phishing URL scanner',
  '/vulnerabilities': 'Vulnerability management',
  '/network': 'Network monitoring',
  '/forensics': 'Digital forensics',
  '/automation': 'Security automation',
  '/reports': 'Reports and analytics',
  '/simulations': 'Threat simulation lab',
  '/users': 'People and access',
  '/settings': 'Settings',
  '/demo-data': 'Demo data',
};

export function AppShellLayout() {
  const { user, organization, logout, features } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [userOpen, setUserOpen] = useState(false);
  const userRef = useRef<HTMLDivElement>(null);
  const summary = useApi<{ kpis: { incidentsOpen: number; detectionsOpen: number } }>('/overview/summary');
  const demoStatus = useApi<{ hasDemoData: boolean }>('/demo/status');
  const live = useEventStream(() => {}, true);

  const root = `/${location.pathname.split('/')[1] ?? ''}`;
  const title = TITLES[root] ?? 'SecureFlow AI';

  useEffect(() => {
    document.title = `${title} · SecureFlow AI`;
  }, [title]);

  useEffect(() => {
    if (!userOpen) return undefined;
    const onDown = (event: MouseEvent) => {
      if (!userRef.current?.contains(event.target as Node)) setUserOpen(false);
    };
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') setUserOpen(false); };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [userOpen]);

  const counts: Record<string, number> = {
    incidents: summary.data?.kpis.incidentsOpen ?? 0,
    detections: summary.data?.kpis.detectionsOpen ?? 0,
  };

  const nav = NAV.map((group) => ({
    ...group,
    items: group.items.filter((item) => item.to !== '/websites' || features.websiteProtection),
  }));

  const handleLogout = async () => {
    await logout();
    navigate('/login', { replace: true });
  };

  return (
    <AppShell
      height="fill"
      contentPadding={0}
      variant="surface"
      topNav={(
        <TopNav
          label="Product navigation"
          heading={(
            <TopNavHeading
              heading="SecureFlow AI"
              subheading={organization?.name ?? 'Workspace'}
              headingHref="/overview"
              logo={(
                <span
                  aria-hidden="true"
                  style={{
                    display: 'grid', placeItems: 'center', width: 28, height: 28, borderRadius: 8,
                    background: 'var(--color-accent)', color: 'var(--color-on-accent)',
                    fontWeight: 700, fontSize: 12, letterSpacing: '0.02em',
                  }}
                >
                  SF
                </span>
              )}
            />
          )}
          endContent={(
            <div className="row" style={{ gap: 8 }}>
              {demoStatus.data?.hasDemoData && (
                <span className="demo-chip" title="This workspace contains synthetic demo records">
                  <FlaskConical size={12} aria-hidden="true" /> Demo data
                </span>
              )}
              <span className="topbar-cta">
                <Button
                  label="Simulation lab"
                  variant="secondary"
                  size="sm"
                  href="/simulations"
                  icon={<BrainCircuit size={14} aria-hidden="true" />}
                />
              </span>
              <div style={{ position: 'relative' }} ref={userRef}>
                <button
                  className="user-button"
                  onClick={() => setUserOpen((value) => !value)}
                  aria-haspopup="menu"
                  aria-expanded={userOpen}
                  aria-label={`Account menu for ${user?.name}`}
                  type="button"
                >
                  <span className="avatar" aria-hidden="true">{initials(user?.name)}</span>
                  <span style={{ textAlign: 'left', lineHeight: 1.2 }} className="tiny user-meta">
                    <span style={{ display: 'block', fontWeight: 600, color: 'var(--color-text-primary)' }}>{user?.name}</span>
                    <span className="faint">{ROLE_LABEL[user?.role ?? ''] ?? user?.role}</span>
                  </span>
                  <ChevronDown size={13} aria-hidden="true" />
                </button>
                {userOpen && (
                  <div role="menu" style={{
                    position: 'absolute', right: 0, top: 42, width: 232, background: 'var(--color-background-popover)',
                    border: '1px solid var(--color-border-emphasized)', borderRadius: 10, boxShadow: 'var(--shadow-2)', padding: 6, zIndex: 40,
                  }}>
                    <div style={{ padding: '8px 10px 10px', borderBottom: '1px solid var(--color-border)', marginBottom: 4 }}>
                      <p style={{ fontSize: 12.5, fontWeight: 600 }}>{user?.name}</p>
                      <p className="tiny faint">{user?.email}</p>
                    </div>
                    <Link to="/settings" role="menuitem" className="nav-item" style={{ margin: 0 }}>
                      <Settings size={14} aria-hidden="true" /> Settings
                    </Link>
                    <Link to="/users" role="menuitem" className="nav-item" style={{ margin: 0 }}>
                      <Users size={14} aria-hidden="true" /> People and access
                    </Link>
                    <button
                      role="menuitem"
                      className="nav-item"
                      style={{ margin: 0, width: '100%', background: 'none', border: 'none', cursor: 'pointer' }}
                      onClick={handleLogout}
                      type="button"
                    >
                      <LogOut size={14} aria-hidden="true" /> Sign out
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}
        />
      )}
      sideNav={(
        <SideNav
          footer={(
            <div style={{ padding: '10px 12px', borderTop: '1px solid var(--color-border)' }}>
              <div className="row tiny" style={{ gap: 7, color: 'var(--color-text-secondary)' }}>
                <span
                  style={{ width: 7, height: 7, borderRadius: 50, background: live ? 'var(--color-success)' : 'var(--color-text-disabled)', display: 'inline-block' }}
                  aria-hidden="true"
                />
                {live ? 'Live stream connected' : 'Live stream offline'}
              </div>
              <p className="tiny faint" style={{ marginTop: 4 }}>{organization?.name ?? 'Workspace'}</p>
            </div>
          )}
        >
          {nav.map((group) => (
            <SideNavSection key={group.label} title={group.label}>
              {group.items.map((item) => {
                const Icon = item.icon;
                const badgeValue = item.badge ? counts[item.badge] : undefined;
                const selected = location.pathname === item.to || location.pathname.startsWith(`${item.to}/`);
                return (
                  <SideNavItem
                    key={item.to}
                    label={item.label}
                    href={item.to}
                    isSelected={selected}
                    icon={Icon}
                    endContent={badgeValue !== undefined && badgeValue > 0 ? <span className="count">{badgeValue}</span> : undefined}
                  />
                );
              })}
            </SideNavSection>
          ))}
        </SideNav>
      )}
    >
      <div className="page">
        <Outlet />
      </div>
    </AppShell>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: React.ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <Heading level={1} className="page-title">{title}</Heading>
        {subtitle && <Text as="p" type="supporting" className="page-sub">{subtitle}</Text>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  );
}

export function RequireAuth({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  const location = useLocation();
  if (loading) {
    return (
      <div style={{ minHeight: '100vh', display: 'grid', placeItems: 'center' }}>
        <div className="row muted"><Activity size={16} className="spin" aria-hidden="true" /> Loading workspace…</div>
      </div>
    );
  }
  if (!user) {
    return <NavigateToLogin from={location.pathname} />;
  }
  return <>{children}</>;
}

function NavigateToLogin({ from }: { from: string }) {
  const navigate = useNavigate();
  useEffect(() => {
    navigate(`/login?next=${encodeURIComponent(from)}`, { replace: true });
  }, [navigate, from]);
  return <div style={{ minHeight: '100vh', display: 'grid', placeItems: 'center' }}><span className="muted">Redirecting to sign in…</span></div>;
}
