export const API_URL = import.meta.env.VITE_API_URL || (window.location.port === '5173' ? `${window.location.protocol}//${window.location.hostname}:4000` : window.location.origin);
export function token() { return localStorage.getItem('cenasync_token') || ''; }
export async function api<T = any>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers || {});
  if (!(options.body instanceof FormData) && options.body !== undefined) headers.set('Content-Type', 'application/json');
  if (token()) headers.set('Authorization', `Bearer ${token()}`);
  const response = await fetch(`${API_URL}${path}`, { ...options, headers });
  const contentType = response.headers.get('content-type') || '';
  const data = contentType.includes('application/json') ? await response.json() : await response.blob();
  if (!response.ok) throw new Error((data as any)?.error || `Erro ${response.status}`);
  return data as T;
}
export const fileUrl = (filename?: string | null) => filename ? `${API_URL}/api/files/${encodeURIComponent(filename)}` : '';
export const post = <T = any>(path: string, body?: unknown) => api<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) });
export const put = <T = any>(path: string, body: unknown) => api<T>(path, { method: 'PUT', body: JSON.stringify(body) });
export const patch = <T = any>(path: string, body: unknown) => api<T>(path, { method: 'PATCH', body: JSON.stringify(body) });
