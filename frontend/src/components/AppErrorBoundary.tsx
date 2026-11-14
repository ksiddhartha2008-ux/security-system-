import { Component, type ErrorInfo, type ReactNode } from 'react';

type Props = { children: ReactNode };
type State = { error: Error | null };

/** Last resort boundary: never leave the operator with a blank screen. */
export class AppErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('[secureflow] render error', error, info.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', padding: 24 }}>
        <div className="card" style={{ maxWidth: 560, padding: 24 }}>
          <p className="mono" style={{ color: 'var(--color-mint)' }}>UI error</p>
          <h1 style={{ fontSize: 20, marginTop: 6 }}>This view could not be rendered</h1>
          <p className="small muted" style={{ marginTop: 8 }}>
            The error was logged to the browser console. Reload the page, or return to the overview.
          </p>
          <pre className="code-block" tabIndex={0} style={{ marginTop: 12 }}>{this.state.error.message}</pre>
          <div className="row" style={{ marginTop: 14, gap: 8 }}>
            <button className="btn btn-primary" type="button" onClick={() => window.location.assign('/overview')}>Back to overview</button>
            <button className="btn" type="button" onClick={() => window.location.reload()}>Reload</button>
          </div>
        </div>
      </div>
    );
  }
}
