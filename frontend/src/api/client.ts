/**
 * Typed fetch wrapper for the Attack Observatory REST API (prefix /api/v1).
 * Attaches the Bearer token from localStorage and redirects to /login on 401.
 */

export const TOKEN_KEY = 'observatory_token';

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

export type QueryParams = Record<string, string | number | undefined>;

export function withQuery(path: string, params?: QueryParams): string {
  if (!params) return path;
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== '') search.set(key, String(value));
  }
  const qs = search.toString();
  return qs ? `${path}?${qs}` : path;
}

async function parseError(res: Response): Promise<ApiError> {
  let detail = res.statusText || 'Request failed';
  try {
    const body = (await res.json()) as { detail?: unknown };
    if (typeof body.detail === 'string') detail = body.detail;
    else if (body.detail !== undefined) detail = JSON.stringify(body.detail);
  } catch {
    // Response had no JSON body; keep the status text.
  }
  return new ApiError(res.status, detail);
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  headers.set('Accept', 'application/json');
  const token = getToken();
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (init?.body !== undefined) headers.set('Content-Type', 'application/json');

  const res = await fetch(`/api/v1${path}`, { ...init, headers });

  if (res.status === 401 && !path.startsWith('/auth/')) {
    clearToken();
    window.location.assign('/login');
    throw new ApiError(401, 'Session expired');
  }
  if (!res.ok) throw await parseError(res);
  return (await res.json()) as T;
}

export const api = {
  get<T>(path: string, params?: QueryParams): Promise<T> {
    return request<T>(withQuery(path, params));
  },

  post<T>(path: string, body: unknown): Promise<T> {
    return request<T>(path, { method: 'POST', body: JSON.stringify(body) });
  },

  /** Binary download (e.g. IOC exports) that still needs the auth header. */
  async getBlob(path: string, params?: QueryParams): Promise<Blob> {
    const headers = new Headers();
    headers.set('Accept', 'application/octet-stream');
    const token = getToken();
    if (token) headers.set('Authorization', `Bearer ${token}`);

    const res = await fetch(`/api/v1${withQuery(path, params)}`, { headers });
    if (res.status === 401) {
      clearToken();
      window.location.assign('/login');
      throw new ApiError(401, 'Session expired');
    }
    if (!res.ok) throw await parseError(res);
    return res.blob();
  },
};
