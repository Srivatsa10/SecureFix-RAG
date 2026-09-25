import { ApiError, api } from './client';

function mockFetch(response: Response | Error) {
  const fn = vi.fn(() => (response instanceof Error ? Promise.reject(response) : Promise.resolve(response)));
  vi.stubGlobal('fetch', fn);
  return fn;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('api client', () => {
  it('posts JSON and returns the parsed body', async () => {
    const fetchMock = mockFetch(Response.json({ status: 'shipped' }));
    const result = await api.remediate({ code: 'x' });
    expect(result).toEqual({ status: 'shipped' });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('/api/remediations');
    expect(init.method).toBe('POST');
    expect(new Headers(init.headers).get('Content-Type')).toBe('application/json');
  });

  it('surfaces structured backend errors', async () => {
    mockFetch(
      Response.json(
        { error: 'decision_service_unavailable', detail: 'Jev failed', request_id: 'abc123' },
        { status: 502 },
      ),
    );
    const error = await api.remediate({ code: 'x' }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 502, code: 'decision_service_unavailable', requestId: 'abc123' });
  });

  it('flattens FastAPI validation errors', async () => {
    mockFetch(
      Response.json({ detail: [{ loc: ['body', 'code'], msg: 'String should have at least 1 character' }] }, { status: 422 }),
    );
    await expect(api.remediate({ code: '' })).rejects.toThrow('code: String should have at least 1 character');
  });

  it('maps network failures to a friendly error', async () => {
    mockFetch(new TypeError('Failed to fetch'));
    await expect(api.health()).rejects.toMatchObject({ code: 'network_error', status: 0 });
  });
});
