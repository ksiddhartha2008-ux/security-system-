export class ApiError extends Error {
  status: number;
  code: string;
  details?: { path: string; message: string }[];

  constructor(status: number, code: string, message: string, details?: { path: string; message: string }[]) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

type Options = {
  method?: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';
  body?: unknown;
  signal?: AbortSignal;
};

async function request<T>(path: string, { method = 'GET', body, signal }: Options = {}): Promise<T> {
  const headers: Record<string, string> = body === undefined
    ? { accept: 'application/json' }
    : { accept: 'application/json', 'content-type': 'application/json' };
  if (method !== 'GET') {
    const token = document.cookie.match(/(?:^|; )sf_csrf=([^;]+)/)?.[1];
    if (token) headers['x-csrf-token'] = decodeURIComponent(token);
  }
  const response = await fetch(`/api${path}`, {
    method,
    credentials: 'same-origin',
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal,
  });
  const text = await response.text();
  let payload: any = null;
  if (text) {
    try { payload = JSON.parse(text); } catch { payload = null; }
  }
  if (!response.ok) {
    const error = payload?.error;
    throw new ApiError(
      response.status,
      error?.code ?? 'request_failed',
      error?.message ?? `Request failed with status ${response.status}`,
      error?.details,
    );
  }
  // Paginated responses keep their envelope ({ data, meta }); single resources unwrap to the data field.
  if (payload && typeof payload === 'object' && 'meta' in payload) return payload as T;
  return (payload?.data ?? payload) as T;
}

export const api = {
  get: <T>(path: string, signal?: AbortSignal) => request<T>(path, { signal }),
  post: <T>(path: string, body?: unknown) => request<T>(path, { method: 'POST', body: body ?? {} }),
  patch: <T>(path: string, body?: unknown) => request<T>(path, { method: 'PATCH', body: body ?? {} }),
  del: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
  raw: request,
};

export function downloadUrl(path: string) {
  return `/api${path}`;
}

/** Trigger a browser download for a cookie authenticated endpoint. */
export async function download(path: string, filename?: string) {
  const response = await fetch(`/api${path}`, { credentials: 'same-origin' });
  if (!response.ok) {
    let message = `Download failed with status ${response.status}`;
    try { const body = await response.json(); message = body?.error?.message ?? message; } catch { /* no json body */ }
    throw new ApiError(response.status, 'download_failed', message);
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename ?? 'secureflow-export';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
