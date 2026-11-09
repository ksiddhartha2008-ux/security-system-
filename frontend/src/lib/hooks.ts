import { useCallback, useEffect, useRef, useState } from 'react';
import { api, ApiError } from './api';

type ResourceState<T> = {
  data: T | null;
  loading: boolean;
  error: string | null;
  refresh: () => void;
  setData: (value: T | null) => void;
};

/** Minimal fetch hook with abort handling and manual refresh. Path of null skips the request. */
export function useApi<T>(path: string | null, deps: unknown[] = []): ResourceState<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(Boolean(path));
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const mounted = useRef(true);

  useEffect(() => () => { mounted.current = false; }, []);

  useEffect(() => {
    if (!path) { setLoading(false); return undefined; }
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    api.get<T>(path, controller.signal)
      .then((value) => { if (!controller.signal.aborted) setData(value); })
      .catch((err) => {
        if (controller.signal.aborted || err?.name === 'AbortError') return;
        setError(err instanceof ApiError ? err.message : 'Could not load this data');
      })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, tick, ...deps]);

  const refresh = useCallback(() => setTick((t) => t + 1), []);
  return { data, loading, error, refresh, setData };
}

export function useDebounced<T>(value: T, delay = 300): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);
  return debounced;
}

type Toast = { id: number; kind: 'success' | 'error' | 'warn' | 'info'; title: string; body?: string };
let toastId = 0;

export function useToasts() {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((kind: Toast['kind'], title: string, body?: string) => {
    const id = ++toastId;
    setToasts((current) => [...current, { id, kind, title, body }]);
    setTimeout(() => setToasts((current) => current.filter((t) => t.id !== id)), 5000);
  }, []);
  const dismiss = useCallback((id: number) => setToasts((current) => current.filter((t) => t.id !== id)), []);
  return { toasts, push, dismiss };
}

export type ToastApi = ReturnType<typeof useToasts>;

export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.details?.length) return `${err.message}: ${err.details.map((d) => `${d.path} ${d.message}`).join(', ')}`;
    return err.message;
  }
  return err instanceof Error ? err.message : 'Something went wrong';
}

/** Subscribe to the server sent event stream. */
export function useEventStream(onEvent: (event: string, payload: unknown) => void, enabled = true) {
  const [connected, setConnected] = useState(false);
  const handler = useRef(onEvent);
  handler.current = onEvent;

  useEffect(() => {
    if (!enabled) return undefined;
    const source = new EventSource('/api/stream');
    const events = ['connected', 'event.ingested', 'simulation.round', 'simulation.finished', 'simulation.failed', 'phishing.scan_completed'];
    const listeners: [string, (event: MessageEvent) => void][] = [];
    source.onopen = () => setConnected(true);
    source.onerror = () => setConnected(false);
    for (const name of events) {
      const listener = (event: MessageEvent) => {
        try {
          const payload = JSON.parse(event.data);
          if (name === 'connected') setConnected(true);
          handler.current(name, payload);
        } catch { /* ignore malformed frame */ }
      };
      source.addEventListener(name, listener);
      listeners.push([name, listener]);
    }
    return () => {
      for (const [name, listener] of listeners) source.removeEventListener(name, listener);
      source.close();
      setConnected(false);
    };
  }, [enabled]);

  return connected;
}
