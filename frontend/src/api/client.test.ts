import { afterEach, describe, expect, it, vi } from 'vitest'
import { z } from 'zod'
import { ApiError, request, resolveApiBase } from './client'
import { authService } from '@/auth/auth.service'
import { mockBackend, user } from '@/test/utils'

afterEach(() => vi.unstubAllGlobals())

describe('resolveApiBase', () => {
  it('treats a missing or "/" base URL as same origin instead of disabling requests', () => {
    expect(resolveApiBase(undefined)).toEqual({ baseUrl: '', valid: true, error: null })
    expect(resolveApiBase('')).toEqual({ baseUrl: '', valid: true, error: null })
    expect(resolveApiBase(' / ')).toEqual({ baseUrl: '', valid: true, error: null })
  })

  it('accepts absolute http(s) URLs and strips trailing slashes', () => {
    expect(resolveApiBase('http://10.0.0.2:5000/')).toEqual({ baseUrl: 'http://10.0.0.2:5000', valid: true, error: null })
    expect(resolveApiBase('https://soc.example.com/api-root').baseUrl).toBe('https://soc.example.com/api-root')
  })

  it('rejects malformed values with a visible error', () => {
    const r = resolveApiBase('localhost:5000')
    expect(r.valid).toBe(false)
    expect(r.error).toMatch(/localhost:5000/)
  })
})

describe('request()', () => {
  it('calls the same-origin /api path with the session cookie', async () => {
    const { calls } = mockBackend([{ path: '/api/v1/health', body: { ok: true } }])
    await request('/api/v1/health', { schema: z.object({ ok: z.boolean() }) })
    expect(calls[0].url).toBe('/api/v1/health')
    expect(calls[0].init?.credentials).toBe('include')
  })

  it('surfaces the backend error detail instead of returning empty data', async () => {
    mockBackend([{ path: '/api/v1/alerts', status: 503, body: { error: 'Database unavailable' } }])
    await expect(request('/api/v1/alerts', { schema: z.unknown() })).rejects.toMatchObject({
      kind: 'http',
      status: 503,
      message: 'Database unavailable',
    })
  })

  it('reports an unreachable backend as a network error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => Promise.reject(new TypeError('Failed to fetch'))))
    const err = await request('/api/v1/health', { schema: z.unknown() }).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).kind).toBe('network')
  })

  it('rejects responses that do not match the contract', async () => {
    mockBackend([{ path: '/api/v1/health', body: { unexpected: 1 } }])
    await expect(request('/api/v1/health', { schema: z.object({ status: z.string() }) })).rejects.toMatchObject({
      kind: 'invalid_response',
    })
  })

  it('sends FormData without forcing a JSON content type', async () => {
    const { calls } = mockBackend([{ method: 'POST', path: '/api/v1/collector/pcap', body: { status: 'completed' } }])
    const form = new FormData()
    form.append('file', new Blob(['x']), 'a.pcap')
    await request('/api/v1/collector/pcap', { method: 'POST', body: form, schema: z.object({ status: z.string() }) })
    const headers = calls[0].init?.headers as Record<string, string>
    expect(headers['Content-Type']).toBeUndefined()
    expect(calls[0].init?.body).toBe(form)
  })
})

describe('login', () => {
  it('posts credentials to the real backend endpoint and returns the server user', async () => {
    const { calls } = mockBackend([{ method: 'POST', path: '/api/v1/auth/login', body: { user: user('ADMIN') } }])
    const u = await authService.login({ username: 'admin01', password: 'pw' })
    expect(calls[0].url).toBe('/api/v1/auth/login')
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ username: 'admin01', password: 'pw' })
    expect(u.role).toBe('ADMIN')
  })

  it('rejects bad credentials with the backend message', async () => {
    mockBackend([{ method: 'POST', path: '/api/v1/auth/login', status: 401, body: { detail: 'Invalid username or password.' } }])
    await expect(authService.login({ username: 'x', password: 'y' })).rejects.toMatchObject({
      status: 401,
      message: 'Invalid username or password.',
    })
  })
})
