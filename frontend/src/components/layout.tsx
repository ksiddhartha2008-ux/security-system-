import { useEffect, useRef, useState } from 'react';
import { Link, NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import {
  Activity, AlertTriangle, Blocks, BookOpen, BrainCircuit, ChevronDown, Database, FileText, Fingerprint,
  FlaskConical, Gauge, Globe2, LayoutDashboard, LogOut, Menu, Network, Radar, Server,
  Settings, ShieldAlert, ShieldCheck, Siren, Users, X, Search,
} from 'lucide-react';
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

export function AppShell() {
  const { user, organization, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [navOpen, setNavOpen] = useState(false);
  const [userOpen, setUserOpen] = useState(false);
  const userRef = useRef<HTMLDivElement>(null);
  const summary = useApi<{ kpis: { incidentsOpen: number; detectionsOpen: number } }>('/overview/summary');
  const demoStatus = useApi<{ hasDemoData: boolean }>('/demo/status');
  const live = useEventStream(() => {}, true);

  const root = `/${location.pathname.split('/')[1] ?? ''}`;
  const title = TITLES[root] ?? (location.pathname === '/' ? 'SecureFlow AI' : 'SecureFlow AI');

  useEffect(() => {
    document.title = `${title} · SecureFlow AI`;
  }, [title]);

  useEffect(() => {
    setNavOpen(false);
    setUserOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    if (!navOpen) return undefined;
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') setNavOpen(false); };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [navOpen]);

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

  const handleLogout = async () => {
    await logout();
    navigate('/login', { replace: true });
  };

  return (
    <div className="shell">
      <a href="#main" className="skip-link">Skip to main content</a>
      {navOpen && <div className="sidebar-scrim" onClick={() => setNavOpen(false)} aria-hidden="true" />}
      <aside className={`sidebar ${navOpen ? 'open' : ''}`} aria-label="Primary navigation">
        <div className="brand">
          <Link to="/overview" className="row" style={{ gap: 10 }} aria-label="SecureFlow AI home">
            <span className="brand-mark" aria-hidden="true">SF</span>
            <span>
              <span className="brand-name" style={{ display: 'block' }}>SecureFlow AI</span>
              <span className="brand-sub">Security operations</span>
            </span>
          </Link>
          <button className="btn btn-ghost btn-icon mobile-only" style={{ marginLeft: 'auto' }} onClick={() => setNavOpen(false)} aria-label="Close navigation" type="button">
            <X size={16} aria-hidden="true" />
          </button>
        </div>
        <nav className="nav">
          {NAV.map((group) => (
            <div key={group.label}>
              <p className="nav-group-label">{group.label}</p>
              {group.items.map((item) => {
                const Icon = item.icon;
                const badgeValue = item.badge ? counts[item.badge] : undefined;
                return (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    className={({ isActive }) => `nav-item ${isActive || location.pathname.startsWith(`${item.to}/`) ? 'active' : ''}`}
                  >
                    <Icon size={16} aria-hidden="true" />
                    <span>{item.label}</span>
                    {badgeValue !== undefined && badgeValue > 0 && <span className="count">{badgeValue}</span>}
                  </NavLink>
                );
              })}
            </div>
          ))}
        </nav>
        <div style={{ padding: '12px 16px 16px', borderTop: '1px solid var(--color-line)' }}>
          <div className="row tiny" style={{ gap: 7, color: '#94a6b8' }}>
            <span style={{ width: 7, height: 7, borderRadius: 50, background: live ? '#3ddc97' : '#6b7f92', display: 'inline-block' }} aria-hidden="true" />
            {live ? 'Live stream connected' : 'Live stream offline'}
          </div>
          <p className="tiny faint" style={{ marginTop: 4 }}>{organization?.name ?? 'Workspace'}</p>
        </div>
      </aside>

      <div className="main">
        <header className="topbar">
          <button className="btn btn-ghost btn-icon mobile-only" onClick={() => setNavOpen(true)} aria-label="Open navigation" aria-expanded={navOpen} type="button">
            <Menu size={18} aria-hidden="true" />
          </button>
          <div style={{ minWidth: 0 }}>
            <p className="topbar-crumb">{NAV.flatMap((g) => g.items).find((i) => root === i.to)?.label ? 'Workspace' : 'SecureFlow AI'}</p>
            <h1 className="topbar-title">{title}</h1>
          </div>
          <div className="topbar-spacer" />
          {demoStatus.data?.hasDemoData && (
            <span className="demo-chip" title="This workspace contains synthetic demo records">
              <FlaskConical size={12} aria-hidden="true" /> Demo data
            </span>
          )}
          <Link to="/simulations" className="btn btn-sm topbar-cta" style={{ display: 'inline-flex' }}>
            <BrainCircuit size={14} aria-hidden="true" /> Simulation lab
          </Link>
          <div style={{ position: 'relative' }} ref={userRef}>
            <button className="user-button" onClick={() => setUserOpen((v) => !v)} aria-haspopup="menu" aria-expanded={userOpen} aria-label={`Account menu for ${user?.name}`} type="button">
              <span className="avatar" aria-hidden="true">{initials(user?.name)}</span>
              <span style={{ textAlign: 'left', lineHeight: 1.2 }} className="tiny user-meta">
                <span style={{ display: 'block', fontWeight: 600, color: '#e8eef5' }}>{user?.name}</span>
                <span className="faint">{ROLE_LABEL[user?.role ?? ''] ?? user?.role}</span>
              </span>
              <ChevronDown size={13} aria-hidden="true" />
            </button>
            {userOpen && (
              <div role="menu" style={{
                position: 'absolute', right: 0, top: 42, width: 232, background: '#101a23',
                border: '1px solid #2a3a4a', borderRadius: 10, boxShadow: '0 18px 40px rgba(0,0,0,0.45)', padding: 6, zIndex: 40,
              }}>
                <div style={{ padding: '8px 10px 10px', borderBottom: '1px solid #1e2b38', marginBottom: 4 }}>
                  <p style={{ fontSize: 12.5, fontWeight: 600 }}>{user?.name}</p>
                  <p className="tiny faint">{user?.email}</p>
                </div>
                <Link to="/settings" role="menuitem" className="nav-item" style={{ margin: 0 }}>
                  <Settings size={14} aria-hidden="true" /> Settings
                </Link>
                <Link to="/users" role="menuitem" className="nav-item" style={{ margin: 0 }}>
                  <Users size={14} aria-hidden="true" /> People and access
                </Link>
                <button role="menuitem" className="nav-item" style={{ margin: 0, width: '100%', background: 'none', border: 'none', cursor: 'pointer' }} onClick={handleLogout} type="button">
                  <LogOut size={14} aria-hidden="true" /> Sign out
                </button>
              </div>
            )}
          </div>
        </header>
        <main id="main" className="page">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: React.ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1 className="page-title">{title}</h1>
        {subtitle && <p className="page-sub">{subtitle}</p>}
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
        <div className="row muted"><Gauge size={16} className="spin" aria-hidden="true" /> Loading workspace…</div>
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

