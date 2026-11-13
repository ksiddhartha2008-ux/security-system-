import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AlertTriangle, ArrowLeft, Globe2, ShieldCheck } from 'lucide-react';
import { PageHeader } from '../components/layout';
import { Button, Card, Field, InlineNotice, useToast } from '../components/ui';
import { api, ApiError } from '../lib/api';
import { useAuth } from '../lib/auth';
import { errorMessage } from '../lib/hooks';

type Preview = {
  hostname: string;
  hostname_unicode: string;
  scheme: string;
  registrable_domain: string;
  homograph_warning: boolean;
  scope_options: string[];
};

const CRITICALITY = [
  { value: 1, label: 'Very low', hint: 'A brochure site. A compromise would be inconvenient.' },
  { value: 2, label: 'Low', hint: 'Public information only.' },
  { value: 3, label: 'Normal', hint: 'Accounts or customer data are handled here.' },
  { value: 4, label: 'High', hint: 'Payments, personal data or an administrative console.' },
  { value: 5, label: 'Critical', hint: 'The business stops if this site is unavailable or taken over.' },
];

export default function WebsiteNewPage() {
  const { permissions } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();
  const [url, setUrl] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [scope, setScope] = useState<'host' | 'domain'>('host');
  const [criticality, setCriticality] = useState(3);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const check = async () => {
    if (!url.trim()) return;
    setChecking(true);
    setPreviewError(null);
    try {
      const result = await api.post<Preview>('/v1/websites/preview', { url });
      setPreview(result);
      if (!displayName) setDisplayName(result.hostname);
    } catch (err) {
      setPreview(null);
      setPreviewError(err instanceof ApiError ? err.message : 'Could not check this address');
    } finally {
      setChecking(false);
    }
  };

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const result = await api.post<{ site: { id: string } }>('/v1/websites', {
        url, display_name: displayName || undefined, scope, criticality,
      });
      toast.push('success', 'Website registered', 'Publish the TXT record to finish verification.');
      navigate(`/websites/${result.site.id}`);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  if (!permissions.canAdmin) {
    return (
      <>
        <PageHeader title="Add website" />
        <Card><p className="small muted">Only an administrator can register a website. Ask an administrator in your workspace.</p></Card>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Add website"
        subtitle="Step 1 of 5. Verification, key creation, SDK install and connection confirmation continue on the website page, so a refresh resumes where you are."
        actions={<Button variant="ghost" icon={<ArrowLeft size={14} aria-hidden="true" />} onClick={() => navigate('/websites')}>Back to websites</Button>}
      />

      <div className="website-split">
        <Card title="Website details">
          <div className="stack" style={{ gap: 14 }}>
            <Field
              label="Website address"
              htmlFor="website-url"
              hint="Enter the address visitors use. It does not have to be reachable from here."
              error={previewError ?? undefined}
              required
            >
              <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
                <input
                  id="website-url"
                  className="input mono"
                  style={{ flex: 1, minWidth: 200 }}
                  value={url}
                  placeholder="https://shop.example.com"
                  onChange={(event) => { setUrl(event.target.value); setPreview(null); }}
                  onBlur={check}
                  autoComplete="url"
                />
                <Button onClick={check} loading={checking} type="button">Check address</Button>
              </div>
            </Field>

            {preview && (
              <div className="notice" style={{ display: 'grid', gap: 6 }}>
                <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
                  <ShieldCheck size={14} aria-hidden="true" />
                  <span className="small">Hostname: <span className="mono">{preview.hostname}</span></span>
                </div>
                {preview.hostname_unicode !== preview.hostname && (
                  <div className="tiny muted">Display form: <span className="mono">{preview.hostname_unicode}</span></div>
                )}
                <div className="tiny muted">Registrable domain: <span className="mono">{preview.registrable_domain}</span></div>
                {preview.homograph_warning && (
                  <div className="tiny" style={{ color: 'var(--color-warning-text)' }}>
                    <AlertTriangle size={12} aria-hidden="true" style={{ display: 'inline', marginRight: 4 }} />
                    This name uses mixed alphabets or an international form that looks like another name. Check the spelling carefully before you continue.
                  </div>
                )}
              </div>
            )}

            <Field label="Display name" htmlFor="website-name" hint="Shown on dashboards and incidents. Defaults to the hostname.">
              <input id="website-name" className="input" maxLength={100} value={displayName}
                placeholder={preview?.hostname ?? 'Shop'} onChange={(event) => setDisplayName(event.target.value)} />
            </Field>

            <Field label="Scope" htmlFor="website-scope" required hint="Scope cannot be changed later. Register a second website if you need both.">
              <select id="website-scope" className="select" value={scope} onChange={(event) => setScope(event.target.value as 'host' | 'domain')}>
                <option value="host">Only this exact address, host scope</option>
                <option value="domain">This domain and every subdomain, domain scope</option>
              </select>
            </Field>

            {scope === 'host' ? (
              <p className="tiny faint">
                The TXT record is published on the exact hostname. Events are accepted only when the request host equals that name.
              </p>
            ) : (
              <p className="tiny faint">
                The TXT record is published on the main domain, which proves control of every subdomain. Only an administrator of
                that zone can complete this.
              </p>
            )}

            <Field label="Criticality" htmlFor="website-criticality" hint="Used to compute incident priority.">
              <select id="website-criticality" className="select" value={criticality} onChange={(event) => setCriticality(Number(event.target.value))}>
                {CRITICALITY.map((item) => <option key={item.value} value={item.value}>{item.value} — {item.label}</option>)}
              </select>
            </Field>
            <p className="tiny faint">{CRITICALITY.find((item) => item.value === criticality)?.hint}</p>

            {error && <InlineNotice tone="error">{error}</InlineNotice>}

            <div className="row" style={{ justifyContent: 'flex-end', gap: 8 }}>
              <Button variant="ghost" onClick={() => navigate('/websites')} type="button">Cancel</Button>
              <Button variant="primary" onClick={submit} loading={busy} disabled={!url.trim()} type="button" icon={<Globe2 size={14} aria-hidden="true" />}>
                Register and continue
              </Button>
            </div>
          </div>
        </Card>

        <Card title="What happens next">
          <ol className="small muted" style={{ paddingLeft: 18, display: 'grid', gap: 10 }}>
            <li>SecureFlow shows a TXT record with a random token.</li>
            <li>You publish it in your DNS provider. It can take time to spread.</li>
            <li>We check the record now and again on a schedule.</li>
            <li>After verification you create a scoped API key and install the Node SDK.</li>
            <li>The first accepted event marks the connection as live.</li>
          </ol>
          <div className="divider" style={{ margin: '14px 0' }} />
          <p className="tiny faint">
            We never fetch or scan the website. Verification reads a DNS TXT record only, and events arrive from the SDK you install.
          </p>
        </Card>
      </div>
    </>
  );
}
