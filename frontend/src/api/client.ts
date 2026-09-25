import type {
  ExampleCase,
  HealthResponse,
  RemediationRequest,
  RemediationResult,
} from './types';

const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '');

/** An HTTP error from the backend, carrying its structured error body when present. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string | null;

  constructor(status: number, code: string, message: string, requestId: string | null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

interface ErrorBody {
  error?: string;
  detail?: unknown;
  request_id?: string | null;
}

function describeDetail(detail: unknown): string | null {
  if (typeof detail === 'string') return detail;
  // FastAPI validation errors: [{ loc: [...], msg: "..." }, ...]
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item: unknown) => {
        if (typeof item !== 'object' || item === null) return null;
        const { loc, msg } = item as { loc?: unknown[]; msg?: string };
        const field = Array.isArray(loc) ? loc.filter((p) => p !== 'body').join('.') : '';
        return msg ? (field ? `${field}: ${msg}` : msg) : null;
      })
      .filter((m): m is string => m !== null);
    return messages.length ? messages.join('; ') : null;
  }
  return null;
}

async function toApiError(response: Response): Promise<ApiError> {
  let body: ErrorBody = {};
  try {
    body = (await response.json()) as ErrorBody;
  } catch {
    // Non-JSON error body (e.g. a proxy error page); fall back to the status text.
  }
  const message =
    describeDetail(body.detail) ?? (response.statusText || `Request failed (${response.status})`);
  return new ApiError(
    response.status,
    body.error ?? 'http_error',
    message,
    body.request_id ?? response.headers.get('X-Request-ID'),
  );
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set('Content-Type', 'application/json');
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, { ...init, headers });
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error;
    throw new ApiError(0, 'network_error', 'Could not reach the backend. Is it running?', null);
  }
  if (!response.ok) throw await toApiError(response);
  return (await response.json()) as T;
}

export const api = {
  health: (signal?: AbortSignal) =>
    request<HealthResponse>('/api/health', signal ? { signal } : {}),

  examples: (signal?: AbortSignal) =>
    request<ExampleCase[]>('/api/examples', signal ? { signal } : {}),

  remediate: (body: RemediationRequest, signal?: AbortSignal) =>
    request<RemediationResult>('/api/remediations', {
      method: 'POST',
      body: JSON.stringify(body),
      ...(signal ? { signal } : {}),
    }),
};
