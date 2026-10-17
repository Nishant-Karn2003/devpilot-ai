import type { Analysis, DependencyScan, Overview, PatchSuggestion } from './types';

const tokenKey = 'devpilot.access-token';

export function getToken(): string | null {
  return localStorage.getItem(tokenKey);
}

export function saveToken(token: string | null): void {
  if (token) localStorage.setItem(tokenKey, token);
  else localStorage.removeItem(tokenKey);
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getToken();
  const response = await fetch(path, {
    ...init,
    headers: {
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init?.headers,
    },
  });
  if (!response.ok) {
    const detail = await response.json().catch(() => null) as {
      detail?: string | Array<{ msg?: string }>;
    } | null;
    if (response.status === 401 && token) {
      saveToken(null);
      window.dispatchEvent(new Event('devpilot:unauthorized'));
    }
    const message = typeof detail?.detail === 'string'
      ? detail.detail
      : Array.isArray(detail?.detail)
        ? detail.detail.map(item => item.msg ?? 'Invalid request').join('; ')
        : `Request failed (${response.status})`;
    throw new Error(message);
  }
  return response.json() as Promise<T>;
}

export type Credentials = { email: string; password: string };
export async function authenticate(path: 'login' | 'register', credentials: Credentials) {
  const result = await request<{ access_token: string; user: { email: string } }>(`/api/auth/${path}`, {
    method: 'POST', body: JSON.stringify(credentials),
  });
  saveToken(result.access_token);
  return result.user;
}

export const api = {
  overview: () => request<Overview>('/api/analytics/overview'),
  analyses: () => request<Analysis[]>('/api/analyses?limit=50'),
  analysis: (id: string) => request<Analysis>(`/api/analyses/${id}`),
  submit: (input: { code: string; language: string; file_name: string; fail_on_severity: string }) =>
    request<Analysis>('/api/analyses', { method: 'POST', body: JSON.stringify(input) }),
  diff: (diff: string, failOnSeverity: string) => request<Analysis>(
    '/api/diffs', { method: 'POST', body: JSON.stringify({ diff, fail_on_severity: failOnSeverity }) },
  ),
  aiReview: (id: string) => request<{ analysis_id: string; added_findings: number; provider: string | null }>(
    `/api/analyses/${id}/ai-review`, { method: 'POST' },
  ),
  suggestPatch: (analysisId: string, findingId: string) => request<PatchSuggestion>(
    `/api/analyses/${analysisId}/patch-suggestions?finding_id=${encodeURIComponent(findingId)}`,
    { method: 'POST' },
  ),
  decidePatch: (id: string, decision: 'accepted' | 'rejected') => request<PatchSuggestion>(
    `/api/patch-suggestions/${id}`, { method: 'PATCH', body: JSON.stringify({ decision }) },
  ),
  dependencyScans: () => request<DependencyScan[]>('/api/dependency-scans?limit=20'),
  dependencyScan: (id: string) => request<DependencyScan>(`/api/dependency-scans/${id}`),
  scanDependencies: (input: { ecosystem: 'python' | 'npm'; manifest: string; lockfile: string }) =>
    request<DependencyScan>('/api/dependency-scans', { method: 'POST', body: JSON.stringify(input) }),
  health: () => request<{ llm_configured: boolean }>('/health'),
};
