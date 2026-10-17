import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, getToken, saveToken } from './api';

afterEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
});

describe('API client', () => {
  it('adds the active bearer token and returns typed report data', async () => {
    saveToken('test-token');
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      id: 'report-1', status: 'completed', findings: [], summary: {}, quality_gate: {},
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
    const result = await api.analysis('report-1');
    expect(result.id).toBe('report-1');
    expect(fetchMock.mock.calls[0][1]?.headers).toMatchObject({ Authorization: 'Bearer test-token' });
  });

  it('reports backend validation failures and clears tokens on logout', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ detail: 'Invalid source' }), { status: 422 }));
    await expect(api.overview()).rejects.toThrow('Invalid source');
    saveToken('temporary');
    saveToken(null);
    expect(getToken()).toBeNull();
  });

  it('clears an expired bearer token after an unauthorized response', async () => {
    saveToken('expired-token');
    const unauthorized = vi.fn();
    window.addEventListener('devpilot:unauthorized', unauthorized);
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ detail: 'Invalid token' }), { status: 401 }));
    await expect(api.overview()).rejects.toThrow('Invalid token');
    expect(getToken()).toBeNull();
    expect(unauthorized).toHaveBeenCalledOnce();
    window.removeEventListener('devpilot:unauthorized', unauthorized);
  });
});
