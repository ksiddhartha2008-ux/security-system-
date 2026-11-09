import { useState } from 'react';
import { UserPlus, Users } from 'lucide-react';
import { PageHeader } from '../components/layout';
import {
  Badge, Button, Card, ErrorState, Field, Modal, RoleBadge, StatusBadge, TableSkeleton, useToast, InlineNotice,
} from '../components/ui';
import { useApi } from '../lib/hooks';
import { api, ApiError } from '../lib/api';
import { formatDate, initials, timeAgo } from '../lib/format';
import { useAuth } from '../lib/auth';

type UserRow = { id: string; email: string; name: string; role: string; status: string; lastLoginAt: string | null; createdAt: string; isSelf: boolean };

export default function PeoplePage() {
  const { permissions } = useAuth();
  const toast = useToast();
  const users = useApi<UserRow[]>('/settings/users');
  const [createOpen, setCreateOpen] = useState(false);

  const update = async (user: UserRow, patch: Record<string, unknown>) => {
    try {
      await api.patch(`/settings/users/${user.id}`, patch);
      toast.push('success', 'Member updated');
      users.refresh();
    } catch (err) { toast.push('error', 'Update failed', err instanceof ApiError ? err.message : undefined); }
  };

  return (
    <>
      <PageHeader title="People and access" subtitle="Three roles: admin manages the workspace, analyst works the queue, viewer reads. Permissions are enforced on the server."
        actions={permissions.canAdmin ? <Button variant="primary" icon={<UserPlus size={14} aria-hidden="true" />} onClick={() => setCreateOpen(true)}>Add member</Button> : undefined} />

      {!permissions.canAdmin && <InlineNotice tone="info">Only an admin can add members or change roles. You can still see who is in the workspace.</InlineNotice>}

      <Card bodyClass="" className="">
        {users.loading && !users.data ? <TableSkeleton rows={5} cols={5} /> : users.error ? <ErrorState message={users.error} onRetry={users.refresh} /> : (
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>Member</th><th>Email</th><th>Role</th><th>Status</th><th>Last sign in</th><th className="right">Joined</th></tr></thead>
              <tbody>
                {users.data?.map((user) => (
                  <tr key={user.id}>
                    <td>
                      <div className="row" style={{ gap: 9 }}>
                        <span className="avatar" aria-hidden="true">{initials(user.name)}</span>
                        <div>
                          <p style={{ fontWeight: 550 }}>{user.name}{user.isSelf ? ' (you)' : ''}</p>
                          <p className="tiny faint">Joined {formatDate(user.createdAt, false)}</p>
                        </div>
                      </div>
                    </td>
                    <td className="small muted">{user.email}</td>
                    <td>
                      {permissions.canAdmin && !user.isSelf ? (
                        <select className="select" style={{ width: 130, minHeight: 28, padding: '3px 28px 3px 8px' }} value={user.role}
                          onChange={(e) => update(user, { role: e.target.value })} aria-label={`Role for ${user.name}`}>
                          {['admin', 'analyst', 'viewer'].map((role) => <option key={role} value={role}>{role}</option>)}
                        </select>
                      ) : <RoleBadge role={user.role} />}
                    </td>
                    <td><StatusBadge status={user.status} /></td>
                    <td className="small muted">{user.lastLoginAt ? timeAgo(user.lastLoginAt) : 'Never'}</td>
                    <td className="right">
                      {permissions.canAdmin && !user.isSelf && (
                        <Button size="sm" variant="ghost" onClick={() => update(user, { status: user.status === 'active' ? 'disabled' : 'active' })}>
                          {user.status === 'active' ? 'Disable' : 'Enable'}
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="card-foot">
          <p className="tiny faint"><Users size={12} aria-hidden="true" style={{ display: 'inline', marginRight: 5 }} />
            Sessions are invalidated when a member is disabled. You cannot remove your own admin role.</p>
        </div>
      </Card>

      <CreateUserModal open={createOpen} onClose={() => setCreateOpen(false)} onCreated={() => users.refresh()} />
    </>
  );
}

function CreateUserModal({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: () => void }) {
  const toast = useToast();
  const [form, setForm] = useState({ name: '', email: '', role: 'analyst', password: '' });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setErrors({}); setError(null);
    const next: Record<string, string> = {};
    if (form.name.trim().length < 2) next.name = 'Enter the member name';
    if (!/^\S+@\S+\.\S+$/.test(form.email)) next.email = 'Enter a valid email address';
    if (form.password.length < 10) next.password = 'At least 10 characters';
    if (Object.keys(next).length) { setErrors(next); return; }
    setBusy(true);
    try {
      await api.post('/settings/users', { ...form, name: form.name.trim(), email: form.email.trim() });
      toast.push('success', 'Member added', 'Share the temporary password through a secure channel.');
      onCreated(); onClose();
      setForm({ name: '', email: '', role: 'analyst', password: '' });
    } catch (err) {
      if (err instanceof ApiError) { setError(err.message); if (err.details) setErrors(Object.fromEntries(err.details.map((d) => [d.path, d.message]))); }
      else setError('Could not add the member');
    } finally { setBusy(false); }
  };

  return (
    <Modal open={open} onClose={onClose} title="Add a workspace member" subtitle="The password is shown once; ask them to change it after signing in."
      footer={<><Button variant="ghost" onClick={onClose} type="button">Cancel</Button><Button variant="primary" onClick={submit} loading={busy} type="button">Add member</Button></>}>
      {error && <div className="error-box" role="alert">{error}</div>}
      <Field label="Full name" htmlFor="u-name" error={errors.name} required><input id="u-name" className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
      <Field label="Work email" htmlFor="u-email" error={errors.email} required><input id="u-email" className="input" type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></Field>
      <div className="grid grid-2">
        <Field label="Role" htmlFor="u-role">
          <select id="u-role" className="select" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
            <option value="analyst">Security analyst</option>
            <option value="viewer">Viewer</option>
            <option value="admin">Admin</option>
          </select>
        </Field>
        <Field label="Temporary password" htmlFor="u-pass" error={errors.password} required><input id="u-pass" className="input" type="text" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></Field>
      </div>
      <p className="tiny faint">Roles: admin can change settings and roles, analyst can triage and respond, viewer is read only.</p>
    </Modal>
  );
}
