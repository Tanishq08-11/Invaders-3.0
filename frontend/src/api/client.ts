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

const RAW_BASE_URL = ((import.meta.env.VITE_API_BASE_URL as string | undefined) ?? '').trim()
// "/" means same origin: the Flask backend serves the built app, and `npm run dev` proxies /api.
const BASE_URL = RAW_BASE_URL.replace(/\/+$/, '')

export const UNAUTHORIZED_EVENT = 'veylix:unauthorized'
export const notifyUnauthorized = () => window.dispatchEvent(new Event(UNAUTHORIZED_EVENT))

/** Absolute URL for a backend path; used by transfer helpers that bypass JSON parsing. */
export const apiUrl = (path: string) => `${BASE_URL}${path}`

export const isApiConfigured = RAW_BASE_URL.length > 0

interface RequestOptions<T> {
  method?: 'GET' | 'POST' | 'PATCH' | 'DELETE'
  body?: unknown
  schema: z.ZodType<T, unknown>
  signal?: AbortSignal
}

/** Single place that talks to the backend. Validates every response with Zod. */
export async function request<T>(path: string, opts: RequestOptions<T>): Promise<T> {
  if (!isApiConfigured) {
    throw new ApiError('not_configured', 'VITE_API_BASE_URL is not set.')
  }
  let res: Response
  try {
    res = await fetch(`${BASE_URL}${path}`, {
      method: opts.method ?? 'GET',
      // Session is cookie-based (HttpOnly, set by the backend); no tokens are kept in JS-accessible storage.
      credentials: 'include',
      headers: {
        Accept: 'application/json',
        ...(opts.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      },
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      signal: opts.signal,
    })
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e
    throw new ApiError('network', 'Unable to reach the backend.')
  }
  if (res.status === 401) notifyUnauthorized()
  if (!res.ok) {
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
