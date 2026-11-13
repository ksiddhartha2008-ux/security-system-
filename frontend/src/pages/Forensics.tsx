import { useRef, useState } from 'react';
import { Fingerprint, ShieldCheck, Upload } from 'lucide-react';
import { PageHeader } from '../components/layout';
import {
  Badge, Button, Card, Drawer, EmptyState, ErrorState, Field, KeyValue, Modal, Pagination,
  SearchInput, StatusBadge, TableSkeleton, useToast, InlineNotice,
} from '../components/ui';
import { useApi, useDebounced } from '../lib/hooks';
import { api, download, ApiError } from '../lib/api';
import { formatBytes, formatDate, timeAgo } from '../lib/format';
import { useAuth } from '../lib/auth';

type Evidence = {
  id: string; caseRef: string; filename: string; description: string; mimeType: string; sizeBytes: number;
  sha256: string; collectedFrom: string | null; collectedBy: string | null; status: string; createdAt: string;
};
type Detail = Evidence & {
  filePresent: boolean; fileSizeOnDisk: number | null;
  custody: { id: string; action: string; actor: string | null; note: string | null; hashAtAction: string; createdAt: string }[];
};

export default function ForensicsPage() {
  const { permissions } = useAuth();
  const toast = useToast();
  const [page, setPage] = useState(1);
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState<string | null>(null);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const debounced = useDebounced(query, 300);
  const params = new URLSearchParams({ page: String(page), limit: '20' });
  if (debounced.trim()) params.set('q', debounced.trim());
  const evidence = useApi<{ data: Evidence[]; meta: { page: number; limit: number; total: number; totalPages: number } }>(`/forensics?${params.toString()}`);
  const stats = useApi<{ total: number; totalBytes: number; byStatus: { status: string; c: number }[] }>('/forensics/stats');
  const detail = useApi<Detail>(selected ? `/forensics/${selected}` : null);

  const verify = async () => {
    if (!selected) return;
    setVerifying(true);
    try {
      const result = await api.post<{ match: boolean; expected: string; actual: string }>(`/forensics/${selected}/verify`);
      toast.push(result.match ? 'success' : 'error', result.match ? 'Integrity verified' : 'Hash mismatch', result.match ? 'SHA-256 matches the recorded value.' : 'The file on disk no longer matches the recorded hash.');
      detail.refresh();
    } catch (err) { toast.push('error', 'Could not verify', err instanceof ApiError ? err.message : undefined); }
    finally { setVerifying(false); }
  };

  return (
    <>
      <PageHeader title="Digital forensics" subtitle="Sealed artefacts with a SHA-256 computed on intake and every custody action recorded."
        actions={permissions.canWrite ? <Button variant="primary" icon={<Upload size={14} aria-hidden="true" />} onClick={() => setUploadOpen(true)}>Seal evidence</Button> : undefined} />

      <div className="grid grid-4" style={{ marginBottom: 14 }}>
        <div className="card kpi"><div className="kpi-label">Evidence records</div><div className="kpi-value">{stats.data?.total ?? 0}</div><div className="kpi-foot">Across all case references</div></div>
        <div className="card kpi"><div className="kpi-label">Stored volume</div><div className="kpi-value">{formatBytes(stats.data?.totalBytes)}</div><div className="kpi-foot">Files on local disk</div></div>
        <div className="card kpi"><div className="kpi-label">Sealed</div><div className="kpi-value">{stats.data?.byStatus.find((s) => s.status === 'sealed')?.c ?? 0}</div><div className="kpi-foot">No review opened</div></div>
        <div className="card kpi"><div className="kpi-label">In review</div><div className="kpi-value">{stats.data?.byStatus.find((s) => s.status === 'in_review')?.c ?? 0}</div><div className="kpi-foot">Custody actions recorded</div></div>
      </div>

      <Card bodyClass="">
        <div className="card-head">
          <SearchInput value={query} onChange={(v) => { setQuery(v); setPage(1); }} placeholder="Search case, filename or hash" label="Search evidence" />
          <span className="tiny faint" style={{ marginLeft: 'auto' }}>{evidence.data?.meta.total ?? 0} artefacts</span>
        </div>
        {evidence.loading && !evidence.data ? <TableSkeleton rows={6} cols={5} /> : evidence.error ? <ErrorState message={evidence.error} onRetry={evidence.refresh} /> : (
          <>
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>Case</th><th>File</th><th>Size</th><th>SHA-256</th><th>Status</th><th className="right">Sealed</th></tr></thead>
                <tbody>
                  {evidence.data?.data.map((item) => (
                    <tr key={item.id} className="row-link" onClick={() => setSelected(item.id)} tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter') setSelected(item.id); }}>
                      <td className="mono tiny">{item.caseRef}</td>
                      <td>
                        <p style={{ fontWeight: 550 }}>{item.filename}</p>
                        <p className="tiny faint truncate-cell" style={{ maxWidth: 320 }}>{item.description}</p>
                      </td>
                      <td className="num tiny">{formatBytes(item.sizeBytes)}</td>
                      <td className="mono tiny faint">{item.sha256.slice(0, 16)}…</td>
                      <td><StatusBadge status={item.status} /></td>
                      <td className="right tiny faint">{timeAgo(item.createdAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {evidence.data?.data.length === 0 && <EmptyState title="No evidence sealed" body="Seal a file to compute its hash and start the custody record." icon={<Fingerprint size={18} aria-hidden="true" />} />}
            {evidence.data && evidence.data.data.length > 0 && <Pagination page={evidence.data.meta.page} totalPages={evidence.data.meta.totalPages} total={evidence.data.meta.total} onPage={setPage} />}
          </>
        )}
      </Card>

      <Drawer open={Boolean(selected)} onClose={() => setSelected(null)} title={detail.data?.filename ?? 'Evidence'} subtitle={detail.data?.caseRef}
        footer={detail.data ? (
          <div className="row" style={{ marginLeft: 'auto' }}>
            {permissions.canWrite && (
              <Button size="sm" onClick={() => download(`/forensics/${detail.data!.id}/download`, detail.data!.filename).catch((err) => toast.push('error', 'Download failed', err.message))}>Download</Button>
            )}
            {permissions.canWrite && <Button size="sm" variant="primary" onClick={verify} loading={verifying} icon={<ShieldCheck size={13} aria-hidden="true" />}>Verify hash</Button>}
          </div>
        ) : undefined}>
        {detail.loading && <TableSkeleton rows={6} cols={2} />}
        {detail.error && <ErrorState message={detail.error} onRetry={detail.refresh} />}
        {detail.data && (
          <>
            <div className="row wrap" style={{ gap: 8 }}><StatusBadge status={detail.data.status} /><Badge tone="neutral">{detail.data.mimeType}</Badge><span className="tiny faint">{formatBytes(detail.data.sizeBytes)}</span></div>
            <p className="small muted">{detail.data.description}</p>
            <KeyValue items={[
              { label: 'Case', value: detail.data.caseRef },
              { label: 'Collected from', value: detail.data.collectedFrom ?? '—' },
              { label: 'Sealed', value: formatDate(detail.data.createdAt) },
              { label: 'File on disk', value: detail.data.filePresent ? `${formatBytes(detail.data.fileSizeOnDisk)}` : 'Missing' },
            ]} />
            <div>
              <p className="label">SHA-256</p>
              <pre className="code-block">{detail.data.sha256}</pre>
            </div>
            {!detail.data.filePresent && <InlineNotice tone="error">The stored file is missing from disk. The hash record remains, but integrity cannot be verified.</InlineNotice>}
            <div>
              <p className="label">Chain of custody</p>
              <div className="timeline" style={{ marginTop: 8 }}>
                {detail.data.custody.map((entry) => (
                  <div key={entry.id} className="timeline-item">
                    <p className="timeline-time">{formatDate(entry.createdAt)} · {entry.actor ?? 'system'}</p>
                    <p className="timeline-body strong">{entry.action.replace(/_/g, ' ')}</p>
                    {entry.note && <p className="tiny muted">{entry.note}</p>}
                  </div>
                ))}
              </div>
            </div>
          </>
        )}
      </Drawer>

      <UploadModal open={uploadOpen} onClose={() => setUploadOpen(false)} onCreated={() => { evidence.refresh(); stats.refresh(); }} />
    </>
  );
}

const MIME_BY_EXT: Record<string, string> = {
  txt: 'text/plain', log: 'text/plain', csv: 'text/csv', json: 'application/json',
  pdf: 'application/pdf', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', zip: 'application/zip',
};

function UploadModal({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: () => void }) {
  const toast = useToast();
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [form, setForm] = useState({ caseRef: 'CASE-2026-100', description: '', collectedFrom: '' });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setError(null);
    if (!file) { setError('Choose a file to seal'); return; }
    if (!/^[A-Za-z0-9-]{2,40}$/.test(form.caseRef)) { setError('Case reference may contain letters, digits and dashes only'); return; }
    if (file.size > 5 * 1024 * 1024) { setError('Files are limited to 5 MB in this build'); return; }
    const extension = file.name.split('.').pop()?.toLowerCase() ?? '';
    const mimeType = file.type || MIME_BY_EXT[extension] || 'application/octet-stream';
    setBusy(true);
    try {
      const buffer = await file.arrayBuffer();
      let binary = '';
      const bytes = new Uint8Array(buffer);
      for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
      await api.post('/forensics', {
        caseRef: form.caseRef.trim(), filename: file.name, description: form.description.trim(),
        mimeType, contentBase64: btoa(binary), collectedFrom: form.collectedFrom.trim() || undefined,
      });
      toast.push('success', 'Evidence sealed', 'SHA-256 computed on intake.');
      onCreated(); onClose();
      setFile(null); setForm({ ...form, description: '', collectedFrom: '' });
    } catch (err) { setError(err instanceof ApiError ? err.message : 'Could not seal the evidence'); }
    finally { setBusy(false); }
  };

  return (
    <Modal open={open} onClose={onClose} title="Seal new evidence" subtitle="The file is stored locally and hashed. Metadata is recorded in the custody trail."
      footer={<><Button variant="ghost" onClick={onClose} type="button">Cancel</Button><Button variant="primary" onClick={submit} loading={busy} type="button">Seal evidence</Button></>}>
      {error && <div className="error-box" role="alert">{error}</div>}
      <Field label="File" htmlFor="ev-file" hint="Up to 5 MB. Text, CSV, JSON, PDF, PNG, JPEG and ZIP are accepted." required>
        <input id="ev-file" ref={inputRef} type="file" className="input" onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          accept=".txt,.log,.csv,.json,.pdf,.png,.jpg,.jpeg,.zip" />
      </Field>
      <div className="grid grid-2">
        <Field label="Case reference" htmlFor="ev-case" required><input id="ev-case" className="input mono" value={form.caseRef} onChange={(e) => setForm({ ...form, caseRef: e.target.value })} /></Field>
        <Field label="Collected from" htmlFor="ev-from"><input id="ev-from" className="input" value={form.collectedFrom} onChange={(e) => setForm({ ...form, collectedFrom: e.target.value })} placeholder="ws-fin-114" /></Field>
      </div>
      <Field label="Description" htmlFor="ev-desc"><textarea id="ev-desc" className="textarea" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder="What the artefact is and why it matters." /></Field>
    </Modal>
  );
}
