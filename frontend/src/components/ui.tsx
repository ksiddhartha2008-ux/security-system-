import {
  Children, cloneElement, createContext, isValidElement, useCallback, useContext, useEffect, useId, useMemo, useRef, useState,
  type ReactElement, type ReactNode, type ButtonHTMLAttributes,
} from 'react';
import { AlertTriangle, Check, ChevronLeft, ChevronRight, Copy, Inbox, Loader2, Search, X } from 'lucide-react';
import type { Tone } from '../lib/format';
import { Badge as AstryxBadge } from '@astryxdesign/core/Badge';
import { TextInput } from '@astryxdesign/core/TextInput';

/* ------------------------------- badges ------------------------------- */

export function Badge({ tone = 'neutral', children, dot = false }: { tone?: Tone; children: ReactNode; dot?: boolean }) {
  const variant = ({
    critical: 'red', high: 'orange', medium: 'yellow', low: 'blue', info: 'blue',
    neutral: 'gray', mint: 'green', amber: 'yellow', purple: 'purple',
  } as const)[tone] ?? 'gray';
  return (
    <AstryxBadge
      variant={variant}
      label={children}
      icon={dot ? <span aria-hidden="true" style={{ display: 'inline-block', width: 5, height: 5, borderRadius: 50, background: 'currentColor' }} /> : undefined}
    />
  );
}

export function SeverityBadge({ severity }: { severity?: string | null }) {
  const value = (severity ?? 'info').toLowerCase();
  const tone: Tone = value === 'critical' ? 'critical' : value === 'high' ? 'high' : value === 'medium' ? 'medium' : value === 'low' ? 'low' : 'info';
  return <Badge tone={tone} dot>{value}</Badge>;
}

const STATUS_TONES: Record<string, Tone> = {
  open: 'medium', new: 'low', investigating: 'low', contained: 'amber', resolved: 'mint', closed: 'neutral',
  active: 'mint', paused: 'neutral', concluded: 'mint', running: 'low', completed: 'mint', failed: 'critical',
  cancelled: 'critical', draft: 'neutral', queued: 'low', confirmed: 'mint', false_positive: 'neutral',
  pending_approval: 'amber', in_progress: 'amber', remediated: 'mint', accepted: 'neutral', sealed: 'neutral',
  in_review: 'amber', released: 'mint', online: 'mint', offline: 'neutral', quarantined: 'critical', decommissioned: 'neutral',
  connected: 'mint', configured: 'low', unconfigured: 'neutral', disabled: 'neutral', error: 'critical', ready: 'mint',
  monitoring: 'low', retired: 'neutral', low_risk: 'low', suspicious: 'medium', malicious: 'critical', allowed: 'neutral', blocked: 'critical',
};

export function StatusBadge({ status }: { status?: string | null }) {
  const value = (status ?? 'unknown').toLowerCase();
  return <Badge tone={STATUS_TONES[value] ?? 'neutral'}>{value.replace(/_/g, ' ')}</Badge>;
}

export function RiskBadge({ score }: { score?: number | null }) {
  if (score === null || score === undefined) return <span className="faint">—</span>;
  const tone: Tone = score >= 85 ? 'critical' : score >= 70 ? 'high' : score >= 40 ? 'medium' : 'low';
  return <Badge tone={tone}>{score}</Badge>;
}

export function OriginBadge({ origin }: { origin?: string | null }) {
  if (!origin || origin === 'REAL') return null;
  const tone: Tone = origin === 'DEMO' ? 'amber' : origin === 'SIMULATED' ? 'low' : 'neutral';
  return <Badge tone={tone} dot>{origin.toLowerCase()}</Badge>;
}

export function RoleBadge({ role }: { role: string }) {
  const tone: Tone = role === 'admin' ? 'mint' : role === 'analyst' ? 'low' : 'neutral';
  return <Badge tone={tone}>{role}</Badge>;
}

/* ------------------------------- layout ------------------------------- */

export function Card({ title, subtitle, actions, children, footer, className = '', bodyClass = 'card-body' }: {
  title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode; footer?: ReactNode;
  className?: string; bodyClass?: string;
}) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <header className="card-head">
          <div style={{ minWidth: 0 }}>
            {title && <h2 className="card-title">{title}</h2>}
            {subtitle && <p className="card-sub">{subtitle}</p>}
          </div>
          {actions && <div className="row" style={{ marginLeft: 'auto' }}>{actions}</div>}
        </header>
      )}
      <div className={bodyClass}>{children}</div>
      {footer && <div className="card-foot">{footer}</div>}
    </section>
  );
}

export function KeyValue({ items }: { items: { label: string; value: ReactNode }[] }) {
  return (
    <dl className="kv">
      {items.map((item) => (
        <div key={item.label} style={{ display: 'contents' }}>
          <dt>{item.label}</dt>
          <dd>{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

/* ------------------------------- buttons ------------------------------- */

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'default' | 'primary' | 'ghost' | 'danger';
  size?: 'sm' | 'md' | 'lg';
  loading?: boolean;
  icon?: ReactNode;
};

export function Button({ variant = 'default', size = 'md', loading, icon, children, className = '', disabled, ...rest }: ButtonProps) {
  const variantClass = variant === 'primary' ? 'btn-primary' : variant === 'ghost' ? 'btn-ghost' : variant === 'danger' ? 'btn-danger' : '';
  const sizeClass = size === 'sm' ? 'btn-sm' : size === 'lg' ? 'btn-lg' : '';
  return (
    <button className={`btn ${variantClass} ${sizeClass} ${className}`} disabled={disabled || loading} {...rest}>
      {loading ? <Loader2 size={14} className="spin" aria-hidden="true" /> : icon}
      {children}
    </button>
  );
}

/* ------------------------------- inputs ------------------------------- */

export function Field({ label, htmlFor, hint, error, children, required }: {
  label: string; htmlFor?: string; hint?: string; error?: string; children: ReactNode; required?: boolean;
}) {
  const errorId = useId();
  const only = Children.count(children) === 1 ? Children.only(children) : null;
  const control = error && isValidElement<{ 'aria-describedby'?: string; 'aria-invalid'?: boolean }>(only)
    ? cloneElement(only as ReactElement<{ 'aria-describedby'?: string; 'aria-invalid'?: boolean }>, {
      'aria-invalid': true, 'aria-describedby': errorId,
    })
    : children;
  return (
    <div className="field">
      <label className="label" htmlFor={htmlFor}>{label}{required && <span style={{ color: 'var(--color-orange)' }}> *</span>}</label>
      {control}
      {hint && !error && <span className="hint">{hint}</span>}
      {error && <span className="err" id={errorId} role="alert">{error}</span>}
    </div>
  );
}

export function SearchInput({ value, onChange, placeholder = 'Search', label }: {
  value: string; onChange: (value: string) => void; placeholder?: string; label?: string;
}) {
  return (
    <TextInput
      type="search"
      size="sm"
      label={label ?? placeholder}
      isLabelHidden
      placeholder={placeholder}
      value={value}
      onChange={(next) => onChange(next)}
      startIcon={Search}
      hasClear
      width="100%"
      containerClassName="search"
      enterKeyHint="search"
    />
  );
}

export function Checkbox({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <label className="row small" style={{ gap: 8, cursor: 'pointer' }}>
      <input type="checkbox" className="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <span>{label}</span>
    </label>
  );
}

/* ------------------------------- states ------------------------------- */

export function EmptyState({ title, body, action, icon }: { title: string; body?: string; action?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="empty">
      <div className="empty-icon">{icon ?? <Inbox size={18} aria-hidden="true" />}</div>
      <p className="empty-title">{title}</p>
      {body && <p className="empty-body">{body}</p>}
      {action && <div style={{ marginTop: 12 }}>{action}</div>}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="empty" role="alert">
      <div className="empty-icon" style={{ color: 'var(--color-danger-text-2)' }}><AlertTriangle size={18} aria-hidden="true" /></div>
      <p className="empty-title">Could not load this view</p>
      <p className="empty-body">{message}</p>
      {onRetry && <div style={{ marginTop: 12 }}><Button onClick={onRetry} size="sm">Try again</Button></div>}
    </div>
  );
}

export function TableSkeleton({ rows = 6, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="card-body stack" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="row" style={{ gap: 12 }}>
          {Array.from({ length: cols }).map((__, c) => (
            <div key={c} className="skeleton" style={{ height: 12, flex: c === 0 ? 2 : 1 }} />
          ))}
        </div>
      ))}
    </div>
  );
}

export function Progress({ value, label }: { value: number; label?: string }) {
  return (
    <div>
      {label && <div className="row-between tiny faint" style={{ marginBottom: 4 }}><span>{label}</span><span>{value}%</span></div>}
      <div className="progress" role="progressbar" aria-valuenow={value} aria-valuemin={0} aria-valuemax={100} aria-label={label ?? 'Progress'}>
        <div className="progress-bar" style={{ width: `${Math.min(Math.max(value, 0), 100)}%` }} />
      </div>
    </div>
  );
}

export function Tabs<T extends string>({ tabs, active, onChange }: { tabs: { key: T; label: string; count?: number }[]; active: T; onChange: (key: T) => void }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((tab) => (
        <button
          key={tab.key}
          role="tab"
          aria-selected={active === tab.key}
          className={`tab ${active === tab.key ? 'active' : ''}`}
          onClick={() => onChange(tab.key)}
          type="button"
        >
          {tab.label}{tab.count !== undefined ? ` (${tab.count})` : ''}
        </button>
      ))}
    </div>
  );
}

/* ------------------------------- pagination ------------------------------- */

export function Pagination({ page, totalPages, total, onPage }: { page: number; totalPages: number; total: number; onPage: (page: number) => void }) {
  return (
    <div className="pager">
      <span className="pager-info">{total} record{total === 1 ? '' : 's'} · page {page} of {totalPages}</span>
      <div className="row" style={{ gap: 6 }}>
        <Button size="sm" variant="ghost" onClick={() => onPage(page - 1)} disabled={page <= 1} aria-label="Previous page">
          <ChevronLeft size={14} aria-hidden="true" /> Previous
        </Button>
        <Button size="sm" variant="ghost" onClick={() => onPage(page + 1)} disabled={page >= totalPages} aria-label="Next page">
          Next <ChevronRight size={14} aria-hidden="true" />
        </Button>
      </div>
    </div>
  );
}

/* ------------------------------- overlay ------------------------------- */

function useFocusTrap(open: boolean, onClose: () => void) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return undefined;
    const previous = document.activeElement as HTMLElement | null;
    const node = ref.current;
    const focusables = () => Array.from(node?.querySelectorAll<HTMLElement>(
      'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
    ) ?? []).filter((el) => el.offsetParent !== null || el === document.activeElement);

    const first = focusables()[0];
    first?.focus();

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { event.stopPropagation(); onClose(); return; }
      if (event.key !== 'Tab') return;
      const items = focusables();
      if (!items.length) return;
      const firstEl = items[0];
      const lastEl = items[items.length - 1];
      if (event.shiftKey && document.activeElement === firstEl) { event.preventDefault(); lastEl.focus(); }
      else if (!event.shiftKey && document.activeElement === lastEl) { event.preventDefault(); firstEl.focus(); }
    };
    document.addEventListener('keydown', onKeyDown, true);
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKeyDown, true);
      document.body.style.overflow = '';
      previous?.focus?.();
    };
  }, [open, onClose]);
  return ref;
}

export function Modal({ open, onClose, title, subtitle, children, footer, size = 'md' }: {
  open: boolean; onClose: () => void; title: string; subtitle?: string; children: ReactNode; footer?: ReactNode; size?: 'md' | 'lg';
}) {
  const ref = useFocusTrap(open, onClose);
  const titleId = useId();
  if (!open) return null;
  return (
    <div className="overlay" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className={`modal ${size === 'lg' ? 'modal-lg' : ''}`} role="dialog" aria-modal="true" aria-labelledby={titleId} ref={ref}>
        <div className="modal-head">
          <div>
            <h2 className="card-title" id={titleId} style={{ fontSize: 15 }}>{title}</h2>
            {subtitle && <p className="card-sub" style={{ marginTop: 3 }}>{subtitle}</p>}
          </div>
          <button className="btn btn-ghost btn-icon" style={{ marginLeft: 'auto' }} onClick={onClose} aria-label="Close dialog" type="button">
            <X size={16} aria-hidden="true" />
          </button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>
  );
}

export function Drawer({ open, onClose, title, subtitle, children, footer }: {
  open: boolean; onClose: () => void; title: string; subtitle?: string; children: ReactNode; footer?: ReactNode;
}) {
  const ref = useFocusTrap(open, onClose);
  const titleId = useId();
  if (!open) return null;
  return (
    <div className="overlay drawer-wrap" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <aside className="drawer" role="dialog" aria-modal="true" aria-labelledby={titleId} ref={ref}>
        <div className="modal-head">
          <div style={{ minWidth: 0 }}>
            <h2 className="card-title" id={titleId} style={{ fontSize: 15 }}>{title}</h2>
            {subtitle && <p className="card-sub" style={{ marginTop: 3 }}>{subtitle}</p>}
          </div>
          <button className="btn btn-ghost btn-icon" style={{ marginLeft: 'auto' }} onClick={onClose} aria-label="Close panel" type="button">
            <X size={16} aria-hidden="true" />
          </button>
        </div>
        <div className="drawer-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </aside>
    </div>
  );
}

/* ------------------------------- toasts ------------------------------- */

type ToastItem = { id: number; kind: 'success' | 'error' | 'warn' | 'info'; title: string; body?: string };

export function ToastViewport({ toasts, onDismiss }: { toasts: ToastItem[]; onDismiss: (id: number) => void }) {
  return (
    <div className="toasts" aria-live="polite" aria-atomic="false">
      {toasts.map((toast) => (
        <div key={toast.id} className={`toast ${toast.kind === 'error' ? 'error' : toast.kind === 'warn' ? 'warn' : ''}`} role="status">
          <div style={{ marginTop: 1 }}>
            {toast.kind === 'success' ? <Check size={14} color="var(--color-mint)" aria-hidden="true" /> : <AlertTriangle size={14} color={toast.kind === 'error' ? 'var(--color-red)' : 'var(--color-amber)'} aria-hidden="true" />}
          </div>
          <div style={{ flex: 1 }}>
            <div className="toast-title">{toast.title}</div>
            {toast.body && <div className="toast-body">{toast.body}</div>}
          </div>
          <button className="btn btn-ghost btn-icon btn-sm" onClick={() => onDismiss(toast.id)} aria-label="Dismiss notification" type="button">
            <X size={13} aria-hidden="true" />
          </button>
        </div>
      ))}
    </div>
  );
}

export const ToastContext = createContext<{ push: (kind: ToastItem['kind'], title: string, body?: string) => void }>({ push: () => {} });
export const useToast = () => useContext(ToastContext);

/* ------------------------------- misc ------------------------------- */

export function CopyButton({ value, label = 'Copy' }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch { /* clipboard unavailable */ }
  }, [value]);
  return (
    <Button size="sm" variant="ghost" onClick={copy} icon={copied ? <Check size={13} aria-hidden="true" /> : <Copy size={13} aria-hidden="true" />} type="button">
      {copied ? 'Copied' : label}
    </Button>
  );
}

export function ConfirmDialog({ open, title, body, confirmLabel = 'Confirm', destructive, onConfirm, onClose, loading }: {
  open: boolean; title: string; body: string; confirmLabel?: string; destructive?: boolean;
  onConfirm: () => void; onClose: () => void; loading?: boolean;
}) {
  return (
    <Modal open={open} onClose={onClose} title={title} footer={(
      <>
        <Button variant="ghost" onClick={onClose} type="button">Cancel</Button>
        <Button variant={destructive ? 'danger' : 'primary'} onClick={onConfirm} loading={loading} type="button">{confirmLabel}</Button>
      </>
    )}>
      <p className="small muted">{body}</p>
    </Modal>
  );
}

export function InlineNotice({ tone = 'warn', children }: { tone?: 'warn' | 'info' | 'success' | 'error'; children: ReactNode }) {
  const className = tone === 'error' ? 'error-box' : tone === 'success' ? 'success-box' : tone === 'info' ? 'chip' : 'notice';
  return <div className={className}>{children}</div>;
}

export function usePagination(initial = 1) {
  const [page, setPage] = useState(initial);
  return useMemo(() => ({ page, setPage }), [page]);
}
