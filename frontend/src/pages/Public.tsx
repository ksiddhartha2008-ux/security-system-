import { useEffect, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import {
  Activity, ArrowRight, Check, FileSearch, Fingerprint, FlaskConical, Gauge, Info, KeyRound,
  Layers, LockKeyhole, ShieldCheck, Siren, Sparkles,
} from 'lucide-react';
import { useAuth } from '../lib/auth';
import { useApi } from '../lib/hooks';
import { api, ApiError } from '../lib/api';
import { Badge } from '../components/ui';

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
  { icon: Activity, title: 'Event pipeline', body: 'Normalise authentication, endpoint, email and network telemetry into one searchable stream.' },
  { icon: Gauge, title: 'Deterministic detection', body: 'Threshold rules score every detection and store the factors behind the number.' },
  { icon: Siren, title: 'Incident response', body: 'Move an incident from open to contained to resolved, with an immutable timeline.' },
  { icon: FileSearch, title: 'Investigation workspace', body: 'Correlate assets, indicators and analyst notes against high severity telemetry.' },
  { icon: Fingerprint, title: 'Evidence integrity', body: 'Seal artefacts with SHA-256 and record every custody action.' },
  { icon: FlaskConical, title: 'Threat simulation lab', body: 'Rehearse five attack scenarios against synthetic data and read the resulting risk score.' },
];

export function LandingPage() {
  useTitle('Intelligent cybersecurity operations');
  const { user } = useAuth();
  return (
    <div className="public-shell">
      <PublicNav />
      <main className="public-main">
        <section className="hero">
          <div>
            <span className="chip"><Sparkles size={12} aria-hidden="true" /> Security operations for small teams</span>
            <h1 style={{ marginTop: 16 }}>See the signal. Work the incident. Rehearse the attack.</h1>
            <p>
              SecureFlow AI is one workspace for monitoring, detection, incident response and threat simulation.
              It is built for teams that need a defensible process more than another dashboard.
            </p>
            <div className="hero-actions">
              <Link to={user ? '/overview' : '/login'} className="btn btn-primary btn-lg">
                Open the demo workspace <ArrowRight size={15} aria-hidden="true" />
              </Link>
              <a href="#capabilities" className="btn btn-lg">See what is inside</a>
            </div>
            <p className="hero-note">
              The demo workspace ships with synthetic events, assets and incidents. It contacts no production system.
            </p>
          </div>

          <div className="card" style={{ overflow: 'hidden' }}>
            <div className="card-head">
              <div>
                <p className="card-title">Incident queue</p>
                <p className="card-sub">Live view from the demo workspace</p>
              </div>
              <span className="badge badge-mint" style={{ marginLeft: 'auto' }}><span className="dot" />Demo data</span>
            </div>
            <div style={{ padding: '8px 0' }}>
              {[
                { ref: 'INC-2026-1001', title: 'Ransomware behaviour on finance workstation', severity: 'critical', status: 'investigating' },
                { ref: 'INC-2026-1002', title: 'Credential stuffing against the sign-in service', severity: 'high', status: 'contained' },
                { ref: 'INC-2026-1004', title: 'Payroll phishing campaign reported by staff', severity: 'high', status: 'investigating' },
                { ref: 'INC-2026-1003', title: 'API enumeration of customer identifiers', severity: 'medium', status: 'open' },
              ].map((row) => (
                <div key={row.ref} className="row" style={{ padding: '11px 16px', borderBottom: '1px solid #16222d', gap: 10 }}>
                  <span className={`badge badge-${row.severity}`}><span className="dot" />{row.severity}</span>
                  <div style={{ minWidth: 0 }}>
                    <p style={{ fontSize: 12.8, fontWeight: 550 }} className="truncate-cell">{row.title}</p>
                    <p className="tiny faint">{row.ref} · {row.status}</p>
                  </div>
                </div>
              ))}
            </div>
            <div className="card-foot row tiny faint">
              <LockKeyhole size={12} aria-hidden="true" /> Sample rows, not production incidents
            </div>
          </div>
        </section>

        <section id="capabilities">
          <h2 className="section-title">Fifteen modules, one application</h2>
          <div className="feature-grid">
            {CAPABILITIES.map((feature) => {
              const Icon = feature.icon;
              return (
                <article className="card feature" key={feature.title}>
                  <div className="row" style={{ gap: 9, marginBottom: 8 }}>
                    <span style={{ width: 28, height: 28, borderRadius: 7, background: 'rgba(61,220,151,0.09)', display: 'grid', placeItems: 'center', color: '#7defbb' }}>
                      <Icon size={15} aria-hidden="true" />
                    </span>
                    <h3>{feature.title}</h3>
                  </div>
                  <p>{feature.body}</p>
                </article>
              );
            })}
          </div>
        </section>

        <section id="workflow">
          <h2 className="section-title">A process you can audit</h2>
          <div className="grid grid-3">
            {[
              { n: '01', title: 'Collect', body: 'Events arrive through the API from identity, endpoint, email, network and scanner sources. Every record is scoped to your organization.' },
              { n: '02', title: 'Decide', body: 'Rules produce explainable detections. Analysts confirm, dismiss or promote them into incidents with a full timeline.' },
              { n: '03', title: 'Rehearse', body: 'Run credential stuffing, API abuse, phishing, insider and ransomware scenarios on synthetic data, then export the findings.' },
            ].map((step) => (
              <div className="card" key={step.n} style={{ padding: 18 }}>
                <p className="mono" style={{ color: '#3ddc97' }}>{step.n}</p>
                <h3 style={{ marginTop: 6, fontSize: 15 }}>{step.title}</h3>
                <p className="small muted" style={{ marginTop: 6 }}>{step.body}</p>
              </div>
            ))}
          </div>
        </section>

        <section style={{ marginTop: 46 }} className="card">
          <div className="card-body row" style={{ gap: 18, flexWrap: 'wrap' }}>
            <div style={{ flex: 1, minWidth: 260 }}>
              <h2 style={{ fontSize: 19, fontWeight: 620 }}>Start with the demo workspace</h2>
              <p className="small muted" style={{ marginTop: 6 }}>
                Sign in with a seeded account to explore every module. Data is synthetic and clearly labelled.
              </p>
              <ul className="small muted" style={{ margin: '12px 0 0', paddingLeft: 18, display: 'grid', gap: 5 }}>
                <li>Three roles: admin, security analyst and viewer</li>
                <li>Real backend: every button calls an endpoint</li>
                <li>Simulation engine with five scenarios</li>
              </ul>
            </div>
            <Link to="/login" className="btn btn-primary btn-lg">Sign in <ArrowRight size={15} aria-hidden="true" /></Link>
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
              <li key={item.text} className="row" style={{ gap: 10, color: '#b9c8d6', fontSize: 13 }}>
                <span style={{ width: 26, height: 26, borderRadius: 7, background: 'rgba(61,220,151,0.1)', display: 'grid', placeItems: 'center', color: '#7defbb' }}>
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
  const next = params.get('next') ?? '/overview';
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
      navigate('/overview', { replace: true });
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
          <p className="small muted">Already have an account? <Link to="/login" style={{ color: '#7defbb' }}>Sign in</Link></p>
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
        <div className="stack" style={{ marginTop: 24, fontSize: 13.5, lineHeight: 1.65, color: '#c3d2df' }}>
          <section>
            <h2 style={{ fontSize: 16, color: '#e8eef5' }}>What this deployment stores</h2>
            <p style={{ marginTop: 6 }}>
              Account records (name, email, role, organization) are stored in a local SQLite database next to the application.
              Passwords are stored as scrypt hashes, never in plain text. Security events, assets, incidents, investigations,
              indicators, vulnerability records, simulations and uploaded evidence are stored in the same database, plus the
              evidence files on local disk. Sessions are stored as SHA-256 hashes of a random token with a seven day expiry.
            </p>
          </section>
          <section>
            <h2 style={{ fontSize: 16, color: '#e8eef5' }}>Cookies</h2>
            <p style={{ marginTop: 6 }}>
              One cookie is set: <code className="mono">sf_session</code>. It is HttpOnly, SameSite=Lax, and used only to keep you
              signed in. No analytics, advertising or third-party cookies are set by this application.
            </p>
          </section>
          <section>
            <h2 style={{ fontSize: 16, color: '#e8eef5' }}>Data that can leave the platform</h2>
            <p style={{ marginTop: 6 }}>
              If a VirusTotal or AbuseIPDB API key is configured by the operator, indicators you look up (IP addresses, domains,
              URLs or file hashes) are sent to that provider. If no key is configured, lookups stay local and the interface says so.
              The phishing scanner fetches the URL you submit and every redirect it follows, which reveals your server IP to that host.
              No outbound reputation call is made unless the corresponding key exists.
            </p>
          </section>
          <section>
            <h2 style={{ fontSize: 16, color: '#e8eef5' }}>Retention and deletion</h2>
            <p style={{ marginTop: 6 }}>
              The workspace settings include a retention target in days. Retention is a configuration value in this build and is not
              enforced by an automatic deletion job, so records remain until an operator removes them. Account deletion and bulk export
              are not implemented as self-service features. Ask the workspace administrator, who can remove records directly from the
              deployment.
            </p>
          </section>
          <section>
            <h2 style={{ fontSize: 16, color: '#e8eef5' }}>Contact</h2>
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
        <div className="stack" style={{ marginTop: 24, fontSize: 13.5, lineHeight: 1.65, color: '#c3d2df' }}>
          <section>
            <h2 style={{ fontSize: 16, color: '#e8eef5' }}>What this software is</h2>
            <p style={{ marginTop: 6 }}>
              SecureFlow AI is a security operations workspace. It records events, computes deterministic detections, manages incidents,
              stores evidence and runs synthetic attack simulations. Detection scores and simulation outcomes are advisory. They are not a
              guarantee that a system is compromised or safe.
            </p>
          </section>
          <section>
            <h2 style={{ fontSize: 16, color: '#e8eef5' }}>Acceptable use</h2>
            <p style={{ marginTop: 6 }}>
              Use the platform only on systems and data you are authorised to handle. Do not use the URL scanner to probe networks you do
              not control; it refuses loopback, private, link local and reserved addresses, but that control is not a substitute for
              authorisation. Do not upload evidence containing data you have no lawful basis to process.
            </p>
          </section>
          <section>
            <h2 style={{ fontSize: 16, color: '#e8eef5' }}>Simulations</h2>
            <p style={{ marginTop: 6 }}>
              Simulations run entirely on synthetic data inside the application. They do not attack real systems, and their results must
              not be presented as real detections or predictions. Every simulation report carries this label.
            </p>
          </section>
          <section>
            <h2 style={{ fontSize: 16, color: '#e8eef5' }}>Availability and liability</h2>
            <p style={{ marginTop: 6 }}>
              This is a self-hosted build provided as is, without warranty. The operator is responsible for backups, access control,
              patching and lawful operation. To the extent permitted by law, the authors are not liable for loss arising from use of the
              software.
            </p>
          </section>
          <section>
            <h2 style={{ fontSize: 16, color: '#e8eef5' }}>Third party components</h2>
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
        <p className="mono" style={{ color: '#3ddc97' }}>404</p>
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
