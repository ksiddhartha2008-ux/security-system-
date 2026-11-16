import { useEffect, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import {
  Activity, ArrowRight, Check, FileSearch, Fingerprint, FlaskConical, Gauge, Globe2, Info, KeyRound,
  Layers, Menu, ShieldCheck, Siren, X,
} from 'lucide-react';
import { useAuth } from '../lib/auth';
import { useApi } from '../lib/hooks';
import { api, ApiError } from '../lib/api';
import { Badge } from '../components/ui';
import { ThemeSwitch } from '../components/ThemeSwitch';
import { PublicShader } from '../components/PublicShader';
import { AnimatedMetric, ScrollReveal } from '../components/motion';
import './landing.css';

export function useTitle(title: string) {
  useEffect(() => {
    document.title = `${title} · SecureFlow AI`;
  }, [title]);
}

function PublicNav() {
  const { user } = useAuth();
  return (
    <nav className="public-nav" aria-label="Main">
      <Link to="/" className="row" style={{ gap: 10 }} aria-label="SecureFlow AI home">
        <span className="brand-mark" aria-hidden="true">SF</span>
        <span>
          <span className="brand-name" style={{ display: 'block' }}>SecureFlow AI</span>
          <span className="brand-sub">Security operations workspace</span>
        </span>
      </Link>
      <div className="public-nav-links">
        <a href="#capabilities">Capabilities</a>
        <a href="#workflow">How it works</a>
        {user ? (
          <Link to="/overview" className="btn btn-primary btn-sm">Open workspace</Link>
        ) : (
          <>
            <Link to="/login">Sign in</Link>
            <Link to="/signup" className="btn btn-primary btn-sm">Create account</Link>
          </>
        )}
      </div>
    </nav>
  );
}

function PublicFooter() {
  return (
    <footer className="footer">
      <div className="footer-inner">
        <span>SecureFlow AI {new Date().getFullYear()}</span>
        <span className="faint">Demo workspace populated with synthetic records</span>
        <div className="row" style={{ gap: 16, marginLeft: 'auto' }}>
          <Link to="/privacy">Privacy</Link>
          <Link to="/terms">Terms</Link>
          <Link to="/login">Sign in</Link>
        </div>
      </div>
    </footer>
  );
}

const CAPABILITIES = [
  { icon: Activity, title: 'Live monitoring', tag: 'Visibility layer', body: 'Normalise authentication, endpoint, email and network telemetry into one searchable stream.' },
  { icon: Gauge, title: 'Explainable detection', tag: 'Detection layer', body: 'Threshold rules score every detection and store the factors behind the number.' },
  { icon: Siren, title: 'Incident response', tag: 'Response workflow', body: 'Move an incident from open to contained to resolved, with an immutable timeline.' },
  { icon: FileSearch, title: 'Investigation workspace', tag: 'Context layer', body: 'Correlate assets, indicators and analyst notes against high severity telemetry.' },
  { icon: Fingerprint, title: 'Evidence integrity', tag: 'Investigation layer', body: 'Seal artefacts with SHA-256 and record every custody action.' },
  { icon: FlaskConical, title: 'Threat simulation lab', tag: 'Synthetic rehearsal', body: 'Rehearse five attack scenarios against synthetic data and read the resulting risk score.' },
];

const LANDING_STATS = [
  { value: 15, label: 'Platform modules' },
  { value: 3, label: 'Workspace roles' },
  { value: 5, label: 'Simulation scenarios' },
  { value: 41, label: 'Database tables' },
];

const TRISHIELD_LAYERS = [
  {
    icon: Globe2,
    title: 'Perimeter and network',
    tag: 'Layer 1',
    body: 'nftables and Cloudflare connectors, plus Suricata and WAF feeds. A rule counts only after the provider confirms it and it can be rolled back.',
  },
  {
    icon: ShieldCheck,
    title: 'Application and identity',
    tag: 'Layer 2',
    body: 'Sessions, roles, tenant scoping, MFA and the audit chain. Authorisation is enforced on the server, never by a hidden route.',
  },
  {
    icon: Fingerprint,
    title: 'Endpoint and data',
    tag: 'Layer 3',
    body: 'Wazuh telemetry, ClamAV evidence state and endpoint health. A scanner that is down is never reported as clean.',
  },
];

const LANDING_LINKS = [
  { href: '#platform', label: 'Platform' },
  { href: '#workflow', label: 'How it works' },
  { href: '#trishield', label: 'TriShield' },
  { href: '#security', label: 'Security' },
  { href: '#status', label: 'Status' },
];

function LandingWave() {
  return (
    <div className="lp-wave" aria-hidden="true">
      <div className="lp-wave-track">
        {[0, 1].map((copy) => (
          <svg key={copy} viewBox="0 0 600 70" preserveAspectRatio="none">
            <path d="M0 35 Q75 0 150 35 T300 35 T450 35 T600 35" fill="none" style={{ stroke: 'var(--color-blue)' }} strokeOpacity="0.55" strokeWidth="2" />
            <path d="M0 48 Q75 14 150 48 T300 48 T450 48 T600 48" fill="none" style={{ stroke: 'var(--color-violet)' }} strokeOpacity="0.4" strokeWidth="1.5" />
          </svg>
        ))}
      </div>
    </div>
  );
}

function LandingNav() {
  const { user } = useAuth();
  const [open, setOpen] = useState(false);
  const close = () => setOpen(false);
  return (
    <header className="lp-topbar" onKeyDown={(event) => { if (event.key === 'Escape') setOpen(false); }}>
      <div className="lp-wrap lp-nav">
        <Link to="/" className="lp-brand">
          <span className="lp-brand-mark" aria-hidden="true">SF</span>
          <span>SecureFlow <span style={{ color: 'var(--color-blue)' }}>AI</span></span>
          <span className="sr-only">SecureFlow AI home</span>
        </Link>

        <nav className="lp-links" aria-label="Landing navigation">
          {LANDING_LINKS.map((link) => <a key={link.href} href={link.href}>{link.label}</a>)}
        </nav>

        <div className="lp-nav-actions">
          <div className="lp-theme"><ThemeSwitch /></div>
          {user ? (
            <Link to="/overview" className="btn btn-primary btn-sm">Open workspace</Link>
          ) : (
            <>
              <Link to="/login" className="btn btn-sm">Sign in</Link>
              <Link to="/signup" className="btn btn-sm">Create account</Link>
              <Link to="/login" className="btn btn-primary btn-sm">Open demo</Link>
            </>
          )}
          <button
            type="button"
            className="lp-menu-btn"
            aria-expanded={open}
            aria-controls="lp-mobile-nav"
            aria-label={open ? 'Close navigation' : 'Open navigation'}
            onClick={() => setOpen((value) => !value)}
          >
            {open ? <X size={16} aria-hidden="true" /> : <Menu size={16} aria-hidden="true" />}
          </button>
        </div>
      </div>

      {open && (
        <div className="lp-mobile" id="lp-mobile-nav">
          <nav aria-label="Landing navigation mobile">
            {LANDING_LINKS.map((link) => (
              <a key={link.href} href={link.href} onClick={close}>{link.label}</a>
            ))}
            <Link to="/login" onClick={close}>Sign in</Link>
          </nav>
          <div>
            <p className="tiny faint" style={{ marginBottom: 6 }}>Appearance</p>
            <ThemeSwitch />
          </div>
        </div>
      )}
    </header>
  );
}

export function LandingPage() {
  useTitle('Intelligent cybersecurity operations');
  const { user } = useAuth();
  const primary = user ? '/overview' : '/login';

  const spotlight = (event: React.PointerEvent<HTMLElement>) => {
    if (event.pointerType !== 'mouse') return;
    const rect = event.currentTarget.getBoundingClientRect();
    event.currentTarget.style.setProperty('--mx', `${event.clientX - rect.left}px`);
    event.currentTarget.style.setProperty('--my', `${event.clientY - rect.top}px`);
  };

  return (
    <div className="public-shell lp-shell">
      <LandingNav />
      <main>
        <section className="lp-hero">
          <PublicShader />
          <div className="lp-orbit" aria-hidden="true" />
          <div className="lp-wrap lp-hero-content">
            <span className="lp-eyebrow"><span className="lp-pulse" aria-hidden="true" /> Intelligent security operations</span>
            <h1>See the signal.<br /><span className="lp-gradient">Stop the threat.</span></h1>
            <p className="lp-lead">
              One command center for monitoring, detection, investigation and response.
              SecureFlow AI turns scattered signals into a security workflow your team can explain and audit.
            </p>
            <div className="lp-actions">
              <Link to={primary} className="btn btn-primary">
                {user ? 'Open the workspace' : 'Open the demo workspace'} <ArrowRight size={15} aria-hidden="true" />
              </Link>
              <a href="#platform" className="btn">See what is inside</a>
            </div>
            <p className="lp-micro">Unified visibility · Explainable detection · Human-approved response</p>
          </div>

          <div className="lp-wrap lp-preview-wrap">
            <div className="lp-preview">
              <div className="lp-preview-inner">
                <div className="lp-preview-top">
                  <div className="lp-preview-brand">
                    <span style={{ color: 'var(--color-blue)' }} aria-hidden="true">⬡</span> SecureFlow command center
                  </div>
                  <div className="lp-preview-live">● Illustrative preview</div>
                </div>
                <div className="lp-preview-tiles">
                  {[
                    { label: 'Monitoring', value: 'Streaming', note: 'Continuously' },
                    { label: 'Detection', value: 'Explainable', note: 'Stored factors' },
                    { label: 'Response', value: 'Approval gated', note: 'Server side' },
                    { label: 'Evidence', value: 'Hash sealed', note: 'SHA-256' },
                  ].map((tile) => (
                    <div className="lp-tile" key={tile.label}>
                      <small>{tile.label}</small>
                      <strong>{tile.value}</strong>
                      <em>{tile.note}</em>
                    </div>
                  ))}
                </div>
                <div className="lp-preview-lower">
                  <div className="lp-panel">
                    <h4>Signal path</h4>
                    <div className="lp-path">
                      {['Collect and normalise', 'Detect and score', 'Investigate with context', 'Respond with approval'].map((step) => (
                        <span className="lp-path-step" key={step}><i aria-hidden="true" />{step}</span>
                      ))}
                    </div>
                  </div>
                  <div className="lp-panel">
                    <h4>Sample signals</h4>
                    <div className="lp-signal"><span>Failed sign-in burst</span><b>HIGH</b></div>
                    <div className="lp-signal"><span>New site key created</span><b>REVIEW</b></div>
                    <div className="lp-signal"><span>Endpoint isolated</span><b className="ok">CONTAINED</b></div>
                  </div>
                </div>
              </div>
            </div>
            <p className="lp-preview-note">Illustrative interface with sample labels. No live customer data.</p>
          </div>
        </section>

        <LandingWave />

        <section id="platform" className="lp-section">
          <div className="lp-wrap">
            <ScrollReveal className="lp-section-head">
              <span className="lp-kicker">The platform</span>
              <h2>From noisy signals to <span className="lp-gradient">decisive action.</span></h2>
              <p className="lp-section-copy">
                Fifteen connected modules cover visibility, detection, investigation and response.
                Each one reads and writes the same workspace data, so context follows the incident.
              </p>
            </ScrollReveal>
            <div className="lp-features">
              {CAPABILITIES.map((feature, index) => {
                const Icon = feature.icon;
                return (
                  <ScrollReveal
                    as="article"
                    className="lp-feature"
                    delay={index * 55}
                    key={feature.title}
                    onPointerMove={spotlight}
                  >
                    <div className="lp-feature-icon"><Icon size={19} aria-hidden="true" /></div>
                    <h3>{feature.title}</h3>
                    <p>{feature.body}</p>
                    <span className="lp-tag">{feature.tag}</span>
                  </ScrollReveal>
                );
              })}
            </div>
          </div>
        </section>

        <div className="lp-band">
          <div className="lp-wrap lp-stats">
            {LANDING_STATS.map((stat) => (
              <ScrollReveal className="lp-stat" key={stat.label}>
                <strong><AnimatedMetric value={stat.value} /></strong>
                <span>{stat.label}</span>
              </ScrollReveal>
            ))}
          </div>
        </div>

        <section id="workflow" className="lp-section">
          <div className="lp-wrap">
            <ScrollReveal className="lp-section-head">
              <span className="lp-kicker">How it works</span>
              <h2>A connected path from <span className="lp-gradient">event to outcome.</span></h2>
              <p className="lp-section-copy">
                The workflow keeps evidence, decisions and response activity connected instead of
                spread across disconnected tools.
              </p>
            </ScrollReveal>
            <ol className="lp-steps">
              {[
                { title: 'Collect and normalise', body: 'Receive security events from configured sources, validate them and normalise the data for analysis.' },
                { title: 'Detect and prioritise', body: 'Apply deterministic rules, correlate related signals and calculate risk so attention goes to what matters.' },
                { title: 'Investigate with context', body: 'Review incident details, assets, intelligence and evidence in one workspace with one timeline.' },
                { title: 'Respond and record', body: 'Coordinate authorised response, keep the audit trail and report the outcome without losing history.' },
              ].map((step, index) => (
                <ScrollReveal as="li" className="lp-step" delay={index * 55} key={step.title}>
                  <span className="lp-step-n" aria-hidden="true">{String(index + 1).padStart(2, '0')}</span>
                  <h3>{step.title}</h3>
                  <p>{step.body}</p>
                </ScrollReveal>
              ))}
            </ol>
          </div>
        </section>

        <LandingWave />

        <section id="trishield" className="lp-section">
          <div className="lp-wrap">
            <ScrollReveal className="lp-section-head">
              <span className="lp-kicker">TriShield defense</span>
              <h2>Three layers. <span className="lp-gradient">One accountable console.</span></h2>
              <p className="lp-section-copy">
                Perimeter, application and endpoint controls share one event pipeline, one approval queue
                and one audit trail. A connector is never called healthy because a variable exists: every state
                comes from a recorded check with a timestamp, a latency and a result.
              </p>
            </ScrollReveal>
            <div className="lp-features">
              {TRISHIELD_LAYERS.map((layer, index) => {
                const Icon = layer.icon;
                return (
                  <ScrollReveal
                    as="article"
                    className="lp-feature"
                    delay={index * 55}
                    key={layer.title}
                    onPointerMove={spotlight}
                  >
                    <div className="lp-feature-icon"><Icon size={19} aria-hidden="true" /></div>
                    <h3>{layer.title}</h3>
                    <p>{layer.body}</p>
                    <span className="lp-tag">{layer.tag}</span>
                  </ScrollReveal>
                );
              })}
            </div>
            <ScrollReveal className="lp-status" delay={60}>
              <Info size={18} className="lp-status-icon" aria-hidden="true" />
              <p>
                <b>AI assists. Deterministic checks decide.</b> Every score shows the stored factors behind it,
                no model can approve a firewall change, and a block stays a proposal until an administrator
                approves it and the provider confirms the rule.
              </p>
            </ScrollReveal>
          </div>
        </section>

        <section id="security" className="lp-section">
          <div className="lp-wrap lp-split">
            <ScrollReveal>
              <span className="lp-kicker">Built for accountable security</span>
              <h2>Intelligence with <span className="lp-gradient">human control.</span></h2>
              <p className="lp-section-copy">
                Security decisions need more than a glowing status. SecureFlow AI is built around
                explainable signals, scoped access and approval-aware response.
              </p>
              <ul className="lp-bullets">
                {[
                  ['Explainable detection', 'every score shows the stored factors behind it.'],
                  ['Human-approved response', 'sensitive actions stay subject to server-side authorisation.'],
                  ['Traceable operations', 'the audit chain records security-relevant activity per workspace.'],
                  ['Tenant-aware design', 'the organisation comes from the session, never from the request body.'],
                ].map(([title, body]) => (
                  <li key={title}><span className="lp-check" aria-hidden="true">✓</span><span><b>{title}:</b> {body}</span></li>
                ))}
              </ul>
              <a href="#status" className="btn">Read the honest status</a>
            </ScrollReveal>

            <ScrollReveal className="lp-radar-card" delay={80}>
              <div className="lp-radar-head"><span>Security posture map</span><b>● Signal active</b></div>
              <div className="lp-radar" aria-hidden="true">
                <div className="lp-radar-center">
                  <strong>AUDIT</strong>
                  <span>Traceable by design</span>
                </div>
              </div>
              <div className="lp-radar-head"><span>Detection context</span><b style={{ color: 'var(--color-blue)' }}>Monitoring view</b></div>
            </ScrollReveal>
          </div>
        </section>

        <section id="status" className="lp-section" style={{ paddingTop: 20 }}>
          <div className="lp-wrap">
            <ScrollReveal className="lp-section-head">
              <span className="lp-kicker">Honest status</span>
              <h2>What is real today</h2>
            </ScrollReveal>
            <ScrollReveal className="lp-status">
              <Info size={18} className="lp-status-icon" aria-hidden="true" />
              <p>
                <b>This deployment runs on controlled sample data.</b> Automated response actions are
                simulations, not firewall or endpoint changes. It has not had an independent penetration
                test and is not verified as production ready. The repository documents each limitation.
              </p>
            </ScrollReveal>
          </div>
        </section>

        <section className="lp-cta" id="contact">
          <div className="lp-wrap">
            <ScrollReveal className="lp-cta-box">
              <span className="lp-eyebrow"><span className="lp-pulse" aria-hidden="true" /> Make every signal count</span>
              <h2>Bring your security picture <span className="lp-gradient">into focus.</span></h2>
              <p>Explore the seeded demo workspace and follow one event from ingestion to incident, evidence and report.</p>
              <div className="lp-actions" style={{ marginBottom: 0 }}>
                <Link to={primary} className="btn btn-primary">
                  {user ? 'Open the workspace' : 'Open the demo workspace'} <ArrowRight size={15} aria-hidden="true" />
                </Link>
                {!user && <Link to="/signup" className="btn">Create a workspace</Link>}
              </div>
              <p className="lp-micro" style={{ marginTop: 14 }}>Demo records are synthetic and labelled throughout the product.</p>
            </ScrollReveal>
          </div>
        </section>
      </main>
      <PublicFooter />
    </div>
  );
}

/* --------------------------------- auth --------------------------------- */

function AuthAside() {
  return (
    <aside className="auth-side">
      <Link to="/" className="row" style={{ gap: 10 }}>
        <span className="brand-mark" aria-hidden="true">SF</span>
        <span>
          <span className="brand-name" style={{ display: 'block' }}>SecureFlow AI</span>
          <span className="brand-sub">Security operations workspace</span>
        </span>
      </Link>
      <div style={{ maxWidth: 420 }}>
        <h2 style={{ fontSize: 26, letterSpacing: '-0.03em', lineHeight: 1.25 }}>One place for the alert, the decision and the evidence.</h2>
        <ul style={{ margin: '22px 0 0', padding: 0, listStyle: 'none', display: 'grid', gap: 12 }}>
          {[
            { icon: Activity, text: 'Monitoring, detections and incidents share one data model.' },
            { icon: ShieldCheck, text: 'Every detection stores the factors behind its risk score.' },
            { icon: FlaskConical, text: 'Rehearse five attack scenarios on synthetic data.' },
          ].map((item) => {
            const Icon = item.icon;
            return (
              <li key={item.text} className="row" style={{ gap: 10, color: 'var(--color-ink-soft)', fontSize: 13 }}>
                <span style={{ width: 26, height: 26, borderRadius: 7, background: 'rgba(61,220,151,0.1)', display: 'grid', placeItems: 'center', color: 'var(--color-mint-bright)' }}>
                  <Icon size={14} aria-hidden="true" />
                </span>
                {item.text}
              </li>
            );
          })}
        </ul>
      </div>
      <p className="tiny faint">Demo environment · synthetic records · local SQLite database</p>
    </aside>
  );
}

type DemoAccount = { role: string; name: string; email: string; password: string };

const ROLE_COPY: Record<string, { label: string; body: string }> = {
  Admin: { label: 'Administrator', body: 'Unlocks Settings, People and destructive actions.' },
  Analyst: { label: 'Security Analyst', body: 'Unlocks monitoring, triage and response work.' },
  Viewer: { label: 'Viewer', body: 'Read-only access across every module.' },
};

/** Only same-origin absolute paths may be used as a post-login destination. */
function safeNext(value: string | null): string {
  if (!value || !value.startsWith('/') || value.startsWith('//')) return '/overview';
  return value;
}

export function LoginPage() {
  useTitle('Sign in');
  const { login, user, refresh } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [mode, setMode] = useState<'demo' | 'credentials'>('demo');
  const [selectedEmail, setSelectedEmail] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [mfaStep, setMfaStep] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const next = safeNext(params.get('next'));
  const justRegistered = params.get('registered') === '1';
  const demoAccounts = useApi<DemoAccount[]>('/auth/demo-accounts');
  const accounts = demoAccounts.data ?? [];
  const selected = accounts.find((account) => account.email === selectedEmail) ?? accounts[0];

  useEffect(() => {
    if (user) navigate(next, { replace: true });
  }, [user, navigate, next]);

  useEffect(() => {
    if (!selectedEmail && accounts.length > 0) setSelectedEmail(accounts[0].email);
  }, [accounts, selectedEmail]);

  useEffect(() => {
    if (demoAccounts.data && demoAccounts.data.length === 0) setMode('credentials');
  }, [demoAccounts.data]);

  const completeLogin = async (accountEmail: string, accountPassword: string) => {
    setBusy(true);
    setError(null);
    try {
      const result = await login(accountEmail, accountPassword);
      if (result.mfaRequired) {
        setMfaStep(true);
        setPassword('');
        setCode('');
        return;
      }
      navigate(next, { replace: true });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Sign in failed. Try again.');
    } finally {
      setBusy(false);
    }
  };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!email.trim() || !password) { setError('Enter your email and password'); return; }
    await completeLogin(email.trim(), password);
  };

  const continueWithDemo = async () => {
    if (!selected) return;
    await completeLogin(selected.email, selected.password);
  };

  const verify = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    if (code.trim().length < 6) { setError('Enter the six digit code from your authenticator'); return; }
    setBusy(true);
    try {
      await api.post('/auth/mfa/verify', { code: code.trim() });
      await refresh();
      navigate(next, { replace: true });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Verification failed. Try again.');
    } finally {
      setBusy(false);
    }
  };

  const showDemo = mode === 'demo' && accounts.length > 0;
  const selectedCopy = selected ? ROLE_COPY[selected.role] ?? { label: selected.role, body: '' } : null;

  return (
    <main className="login-page">
      <div className="login-panel">
        <div className="login-brand">
          <span className="login-logo" aria-hidden="true"><ShieldCheck size={22} /></span>
          <div>
            <h1>SecureFlow AI</h1>
            <p>Intelligent cybersecurity platform · MODULE 01</p>
          </div>
        </div>

        {justRegistered && (
          <div className="login-demo-note" role="status">
            <Info size={18} aria-hidden="true" />
            <div>
              <p className="login-note-title">Continue by signing in</p>
              <p>
                If registration can be completed, sign in with your email and password.
                If the address is already registered, use the existing account.
              </p>
            </div>
          </div>
        )}

        <div className="login-demo-note">
          <Info size={18} aria-hidden="true" />
          <div>
            <p className="login-note-title">Demo authentication</p>
            <p>
              This screen signs in with a seeded workspace account through the real API. The backend issues the
              session and enforces the role; a client-side role label never grants access.
            </p>
          </div>
        </div>

        {mfaStep ? (
          <form onSubmit={verify} className="stack" noValidate>
            {error && <div className="error-box" role="alert">{error}</div>}
            <p className="small muted">
              Enter the six digit code from your authenticator app. A recovery code also works here, once.
            </p>
            <div className="field">
              <label className="label" htmlFor="mfa-code">Authentication code</label>
              <input id="mfa-code" className="input mono" inputMode="numeric" autoComplete="one-time-code"
                value={code} onChange={(e) => setCode(e.target.value)} placeholder="123456" autoFocus required />
            </div>
            <button className="btn btn-primary btn-lg" type="submit" disabled={busy}>
              {busy ? 'Verifying…' : <>Verify and sign in <ArrowRight size={15} aria-hidden="true" /></>}
            </button>
            <button className="btn btn-ghost btn-sm" type="button" onClick={() => { setMfaStep(false); setCode(''); setError(null); }}>
              Back to sign in
            </button>
          </form>
        ) : showDemo && selected ? (
          <form onSubmit={(event) => { event.preventDefault(); void continueWithDemo(); }} className="stack" noValidate>
            {error && <div className="error-box" role="alert">{error}</div>}
            <div className="field">
              <label className="label" htmlFor="demo-name">Display name · Required</label>
              <input id="demo-name" className="input" value={selected.name} readOnly />
              <p className="hint">From the seeded account. The server uses its own user record.</p>
            </div>
            <div className="field">
              <label className="label" htmlFor="demo-email">Email · Required</label>
              <input id="demo-email" className="input" value={selected.email} readOnly />
            </div>
            <div className="field">
              <span className="label" id="demo-role-label">Demo role — controls which seeded account signs in</span>
              <div className="demo-segment" role="group" aria-labelledby="demo-role-label">
                {accounts.map((account) => (
                  <button
                    key={account.email}
                    type="button"
                    aria-pressed={account.email === selected.email}
                    onClick={() => { setSelectedEmail(account.email); setError(null); }}
                  >
                    {ROLE_COPY[account.role]?.label ?? account.role}
                  </button>
                ))}
              </div>
              {selectedCopy && <p className="hint">{selectedCopy.body}</p>}
            </div>
            <button className="btn btn-primary btn-lg btn-block" type="submit" disabled={busy}>
              {busy ? 'Signing in…' : <>Continue to console <ArrowRight size={15} aria-hidden="true" /></>}
            </button>
            <div className="login-footnote">
              <Badge tone="neutral">SIMULATED</Badge>
              <span>Demo dataset. No customer credentials are involved.</span>
            </div>
            <button className="btn btn-ghost btn-sm" type="button" onClick={() => { setMode('credentials'); setError(null); }}>
              Sign in with another account
            </button>
          </form>
        ) : mode === 'demo' ? (
          <p className="small muted">Loading demo accounts…</p>
        ) : (
          <>
            <form onSubmit={submit} className="stack" noValidate>
              {error && <div className="error-box" role="alert">{error}</div>}
              <div className="field">
                <label className="label" htmlFor="email">Work email</label>
                <input id="email" className="input" type="email" autoComplete="email" value={email}
                  onChange={(e) => setEmail(e.target.value)} placeholder="you@company.com" required />
              </div>
              <div className="field">
                <label className="label" htmlFor="password">Password</label>
                <input id="password" className="input" type="password" autoComplete="current-password" value={password}
                  onChange={(e) => setPassword(e.target.value)} placeholder="Your password" required />
              </div>
              <button className="btn btn-primary btn-lg btn-block" type="submit" disabled={busy}>
                {busy ? 'Signing in…' : <>Sign in <ArrowRight size={15} aria-hidden="true" /></>}
              </button>
            </form>
            {accounts.length > 0 && (
              <button className="btn btn-ghost btn-sm" type="button" onClick={() => { setMode('demo'); setError(null); }}>
                Back to demo access
              </button>
            )}
          </>
        )}

        <p className="login-legal">
          No account? <Link to="/signup">Create a workspace</Link>. By signing in you accept the{' '}
          <Link to="/terms">terms</Link> and <Link to="/privacy">privacy notice</Link>.
        </p>
      </div>
    </main>
  );
}

export function SignupPage() {
  useTitle('Create a workspace');
  const { register, user } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({ name: '', email: '', password: '', organizationName: '' });
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (user) navigate('/overview', { replace: true });
  }, [user, navigate]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setFieldErrors({});
    const next: Record<string, string> = {};
    if (form.name.trim().length < 2) next.name = 'Enter your full name';
    if (!/^\S+@\S+\.\S+$/.test(form.email)) next.email = 'Enter a valid email address';
    if (form.password.length < 10) next.password = 'Use at least 10 characters';
    if (form.organizationName.trim().length < 2) next.organizationName = 'Enter an organization name';
    if (Object.keys(next).length) { setFieldErrors(next); return; }
    setBusy(true);
    try {
      await register({ ...form, name: form.name.trim(), email: form.email.trim(), organizationName: form.organizationName.trim() });
      navigate('/login?registered=1', { replace: true });
    } catch (err) {
      if (err instanceof ApiError && err.details?.length) {
        setFieldErrors(Object.fromEntries(err.details.map((d) => [d.path, d.message])));
        setError(err.message);
      } else {
        setError(err instanceof ApiError ? err.message : 'Could not create the workspace');
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth-wrap">
      <AuthAside />
      <div className="auth-form-wrap">
        <div className="auth-card stack">
          <div>
            <h1>Create a workspace</h1>
            <p className="sub">You become the first admin. Invite the rest of the team from People.</p>
          </div>
          <form onSubmit={submit} className="stack" noValidate>
            {error && <div className="error-box" role="alert">{error}</div>}
            <div className="field">
              <label className="label" htmlFor="org">Organization name</label>
              <input id="org" className="input" value={form.organizationName} onChange={(e) => setForm({ ...form, organizationName: e.target.value })} placeholder="Northwind Security" />
              {fieldErrors.organizationName && <span className="err">{fieldErrors.organizationName}</span>}
            </div>
            <div className="field">
              <label className="label" htmlFor="name">Your name</label>
              <input id="name" className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Alex Morgan" autoComplete="name" />
              {fieldErrors.name && <span className="err">{fieldErrors.name}</span>}
            </div>
            <div className="field">
              <label className="label" htmlFor="signup-email">Work email</label>
              <input id="signup-email" className="input" type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} placeholder="alex@company.com" autoComplete="email" />
              {fieldErrors.email && <span className="err">{fieldErrors.email}</span>}
            </div>
            <div className="field">
              <label className="label" htmlFor="signup-password">Password</label>
              <input id="signup-password" className="input" type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} autoComplete="new-password" />
              <span className="hint">At least 10 characters. Stored as a scrypt hash.</span>
              {fieldErrors.password && <span className="err">{fieldErrors.password}</span>}
            </div>
            <button className="btn btn-primary btn-lg" type="submit" disabled={busy}>{busy ? 'Creating…' : 'Create workspace'}</button>
          </form>
          <p className="tiny faint">
            By creating an account you accept the <Link to="/terms" style={{ textDecoration: 'underline' }}>terms</Link> and{' '}
            <Link to="/privacy" style={{ textDecoration: 'underline' }}>privacy notice</Link>.
          </p>
          <p className="small muted">Already have an account? <Link to="/login" style={{ color: 'var(--color-mint-bright)' }}>Sign in</Link></p>
        </div>
      </div>
    </div>
  );
}

/* --------------------------------- legal --------------------------------- */

export function PrivacyPage() {
  useTitle('Privacy');
  return (
    <div className="public-shell">
      <PublicNav />
      <main className="public-main" style={{ maxWidth: 820 }}>
        <h1 className="page-title" style={{ fontSize: 30 }}>Privacy notice</h1>
        <p className="small faint" style={{ marginTop: 6 }}>Last updated {new Date().toLocaleDateString('en-GB', { year: 'numeric', month: 'long', day: 'numeric' })}</p>
        <div className="stack" style={{ marginTop: 24, fontSize: 13.5, lineHeight: 1.65, color: 'var(--color-ink-soft)' }}>
          <section>
            <h2 style={{ fontSize: 16, color: 'var(--color-ink-strong)' }}>What this deployment stores</h2>
            <p style={{ marginTop: 6 }}>
              Account records (name, email, role, organization) are stored in a local SQLite database next to the application.
              Passwords are stored as scrypt hashes, never in plain text. Security events, assets, incidents, investigations,
              indicators, vulnerability records, simulations and uploaded evidence are stored in the same database, plus the
              evidence files on local disk. Sessions are stored as SHA-256 hashes of a random token with a seven day expiry.
            </p>
          </section>
          <section>
            <h2 style={{ fontSize: 16, color: 'var(--color-ink-strong)' }}>Cookies</h2>
            <p style={{ marginTop: 6 }}>
              One cookie is set: <code className="mono">sf_session</code>. It is HttpOnly, SameSite=Lax, and used only to keep you
              signed in. No analytics, advertising or third-party cookies are set by this application.
            </p>
          </section>
          <section>
            <h2 style={{ fontSize: 16, color: 'var(--color-ink-strong)' }}>Data that can leave the platform</h2>
            <p style={{ marginTop: 6 }}>
              If a VirusTotal or AbuseIPDB API key is configured by the operator, indicators you look up (IP addresses, domains,
              URLs or file hashes) are sent to that provider. If no key is configured, lookups stay local and the interface says so.
              The phishing scanner fetches the URL you submit and every redirect it follows, which reveals your server IP to that host.
              No outbound reputation call is made unless the corresponding key exists.
            </p>
          </section>
          <section>
            <h2 style={{ fontSize: 16, color: 'var(--color-ink-strong)' }}>Retention and deletion</h2>
            <p style={{ marginTop: 6 }}>
              The workspace settings include a retention target in days. Retention is a configuration value in this build and is not
              enforced by an automatic deletion job, so records remain until an operator removes them. Account deletion and bulk export
              are not implemented as self-service features. Ask the workspace administrator, who can remove records directly from the
              deployment.
            </p>
          </section>
          <section>
            <h2 style={{ fontSize: 16, color: 'var(--color-ink-strong)' }}>Contact</h2>
            <p style={{ marginTop: 6 }}>
              This deployment does not have a verified contact address configured. The operator of this instance is responsible for
              privacy requests. No placeholder contact details are shown.
            </p>
          </section>
          <div className="notice">
            This notice describes the behaviour of this build. It is not legal advice and has not been reviewed by a qualified
            professional. Cookie and privacy rules differ by country.
          </div>
        </div>
      </main>
      <PublicFooter />
    </div>
  );
}

export function TermsPage() {
  useTitle('Terms');
  return (
    <div className="public-shell">
      <PublicNav />
      <main className="public-main" style={{ maxWidth: 820 }}>
        <h1 className="page-title" style={{ fontSize: 30 }}>Terms of use</h1>
        <p className="small faint" style={{ marginTop: 6 }}>Last updated {new Date().toLocaleDateString('en-GB', { year: 'numeric', month: 'long', day: 'numeric' })}</p>
        <div className="stack" style={{ marginTop: 24, fontSize: 13.5, lineHeight: 1.65, color: 'var(--color-ink-soft)' }}>
          <section>
            <h2 style={{ fontSize: 16, color: 'var(--color-ink-strong)' }}>What this software is</h2>
            <p style={{ marginTop: 6 }}>
              SecureFlow AI is a security operations workspace. It records events, computes deterministic detections, manages incidents,
              stores evidence and runs synthetic attack simulations. Detection scores and simulation outcomes are advisory. They are not a
              guarantee that a system is compromised or safe.
            </p>
          </section>
          <section>
            <h2 style={{ fontSize: 16, color: 'var(--color-ink-strong)' }}>Acceptable use</h2>
            <p style={{ marginTop: 6 }}>
              Use the platform only on systems and data you are authorised to handle. Do not use the URL scanner to probe networks you do
              not control; it refuses loopback, private, link local and reserved addresses, but that control is not a substitute for
              authorisation. Do not upload evidence containing data you have no lawful basis to process.
            </p>
          </section>
          <section>
            <h2 style={{ fontSize: 16, color: 'var(--color-ink-strong)' }}>Simulations</h2>
            <p style={{ marginTop: 6 }}>
              Simulations run entirely on synthetic data inside the application. They do not attack real systems, and their results must
              not be presented as real detections or predictions. Every simulation report carries this label.
            </p>
          </section>
          <section>
            <h2 style={{ fontSize: 16, color: 'var(--color-ink-strong)' }}>Availability and liability</h2>
            <p style={{ marginTop: 6 }}>
              This is a self-hosted build provided as is, without warranty. The operator is responsible for backups, access control,
              patching and lawful operation. To the extent permitted by law, the authors are not liable for loss arising from use of the
              software.
            </p>
          </section>
          <section>
            <h2 style={{ fontSize: 16, color: 'var(--color-ink-strong)' }}>Third party components</h2>
            <p style={{ marginTop: 6 }}>
              Optional integrations with MiroFish (AGPL-3.0) and API Anything (MIT) remain under their own licenses and are documented in
              the project repository. No third party code is presented as part of this application's own license.
            </p>
          </section>
          <div className="notice">
            These terms describe this build only. They are not legal advice and need review by a qualified person before production use.
          </div>
        </div>
      </main>
      <PublicFooter />
    </div>
  );
}

export function NotFoundPage() {
  useTitle('Page not found');
  const { user } = useAuth();
  return (
    <div style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', padding: 24 }}>
      <div className="card" style={{ maxWidth: 460, padding: 28, textAlign: 'center' }}>
        <div className="empty-icon" style={{ margin: '0 auto 12px' }}><Layers size={18} aria-hidden="true" /></div>
        <p className="mono" style={{ color: 'var(--color-mint)' }}>404</p>
        <h1 style={{ fontSize: 20, marginTop: 6 }}>That page does not exist</h1>
        <p className="small muted" style={{ marginTop: 8 }}>
          The link may be out of date. The workspace has every module reachable from the sidebar.
        </p>
        <div className="row" style={{ justifyContent: 'center', marginTop: 18 }}>
          <Link to={user ? '/overview' : '/'} className="btn btn-primary">{user ? 'Back to overview' : 'Back to home'}</Link>
        </div>
      </div>
    </div>
  );
}
