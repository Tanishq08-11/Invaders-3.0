import type { z } from 'zod'

export type ApiErrorKind = 'not_configured' | 'network' | 'http' | 'invalid_response'

export class ApiError extends Error {
  kind: ApiErrorKind
  status?: number
  constructor(kind: ApiErrorKind, message: string, status?: number) {
    super(message)
    this.kind = kind
    this.status = status
  }
}

export interface ApiBaseConfig {
  /** Prefix for every request ('' = same origin). */
  baseUrl: string
  /** False only when VITE_API_BASE_URL is set to something that is not a usable URL. */
  valid: boolean
  /** Why the configuration was rejected (shown in the UI). */
  error: string | null
}

/**
 * VITE_API_BASE_URL handling:
 *   unset / empty / "/"   → same origin. Flask serves the built app; `npm run dev` proxies /api.
 *   http(s)://host[:port] → a separately hosted backend (needs CORS_ORIGINS on the backend).
 *   anything else         → rejected with a visible configuration error (never a silent no-op).
 */
export function resolveApiBase(raw: string | undefined): ApiBaseConfig {
  const value = (raw ?? '').trim()
  if (value === '' || value === '/') return { baseUrl: '', valid: true, error: null }
  if (/^https?:\/\/[^/\s]+(\/[^\s]*)?$/i.test(value)) return { baseUrl: value.replace(/\/+$/, ''), valid: true, error: null }
  return {
    baseUrl: '',
    valid: false,
    error: `VITE_API_BASE_URL "${value}" is not "/" or an http(s):// URL.`,
  }
}

const API_BASE = resolveApiBase(import.meta.env.VITE_API_BASE_URL as string | undefined)
const BASE_URL = API_BASE.baseUrl
export const apiConfigError = API_BASE.error

export const UNAUTHORIZED_EVENT = 'veylix:unauthorized'
export const notifyUnauthorized = () => window.dispatchEvent(new Event(UNAUTHORIZED_EVENT))

/** Absolute URL for a backend path; used by transfer helpers that bypass JSON parsing. */
export const apiUrl = (path: string) => `${BASE_URL}${path}`

/** True unless the configured base URL is malformed. A missing value means same origin. */
export const isApiConfigured = API_BASE.valid
/** Cross-origin backends need credentialed EventSource/fetch; same-origin needs nothing extra. */
export const isCrossOrigin = BASE_URL !== ''

interface RequestOptions<T> {
  method?: 'GET' | 'POST' | 'PATCH' | 'DELETE'
  /** JSON body, or FormData for multipart uploads. */
  body?: unknown
  schema: z.ZodType<T, unknown>
  signal?: AbortSignal
  /** Statuses whose JSON body is still a valid (parsed) response, e.g. a 422 PCAP summary. */
  acceptStatus?: number[]
}

/** Single place that talks to the backend. Validates every response with Zod. */
export async function request<T>(path: string, opts: RequestOptions<T>): Promise<T> {
  if (!isApiConfigured) {
    throw new ApiError('not_configured', apiConfigError ?? 'The backend URL is not configured.')
  }
  const isForm = typeof FormData !== 'undefined' && opts.body instanceof FormData
  let res: Response
  try {
    res = await fetch(`${BASE_URL}${path}`, {
      method: opts.method ?? 'GET',
      // Session is cookie-based (HttpOnly, set by the backend); no tokens are kept in JS-accessible storage.
      credentials: 'include',
      headers: {
        Accept: 'application/json',
        ...(opts.body !== undefined && !isForm ? { 'Content-Type': 'application/json' } : {}),
      },
      body: opts.body === undefined ? undefined : isForm ? (opts.body as FormData) : JSON.stringify(opts.body),
      signal: opts.signal,
    })
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e
    throw new ApiError('network', 'Unable to reach the backend.')
  }
  if (res.status === 401) notifyUnauthorized()
  if (!res.ok && !opts.acceptStatus?.includes(res.status)) {
    let detail = ''
    try {
      const j = (await res.json()) as { detail?: unknown; message?: unknown; error?: unknown }
      detail =
        typeof j.detail === 'string' ? j.detail
        : typeof j.message === 'string' ? j.message
        : typeof j.error === 'string' ? j.error
        : ''
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError('http', detail || `Backend responded with HTTP ${res.status}.`, res.status)
  }
  let json: unknown
  try {
    json = await res.json()
  } catch {
    throw new ApiError('invalid_response', 'Backend returned a non-JSON response.', res.status)
  }
  const parsed = opts.schema.safeParse(json)
  if (!parsed.success) {
    console.error('[api] response failed validation for', path, parsed.error.issues)
    throw new ApiError('invalid_response', 'Backend response did not match the expected contract.', res.status)
  }
  return parsed.data
}
