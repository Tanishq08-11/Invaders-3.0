import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { vi } from 'vitest'
import { AuthProvider } from '@/auth/AuthProvider'

export type Route = { method?: string; path: string | RegExp; status?: number; body: unknown }

/** fetch() stub answering by method + path; records every call. Unknown routes → 404. */
export function mockBackend(routes: Route[]) {
  const calls: { method: string; url: string; init?: RequestInit }[] = []
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = (init?.method ?? 'GET').toUpperCase()
    calls.push({ method, url, init })
    const path = url.replace(/^https?:\/\/[^/]+/, '')
    const route = routes.find(
      (r) => (r.method ?? 'GET') === method && (typeof r.path === 'string' ? path.split('?')[0] === r.path : r.path.test(path)),
    )
    if (!route) return new Response(JSON.stringify({ detail: 'not found' }), { status: 404 })
    return new Response(JSON.stringify(route.body), {
      status: route.status ?? 200,
      headers: { 'Content-Type': 'application/json' },
    })
  })
  vi.stubGlobal('fetch', fetchMock)
  return { calls, fetchMock }
}

export function renderWithProviders(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AuthProvider>
        <MemoryRouter>{ui}</MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>,
  )
}

export const user = (role: 'EMPLOYEE' | 'SECURITY_ANALYST' | 'ADMIN') => ({
  id: 1,
  username: role.toLowerCase(),
  display_name: `Test ${role}`,
  role,
  department: 'SOC',
})

export const collectorStatus = (over: Record<string, unknown> = {}) => ({
  mode: 'stopped',
  is_running: false,
  is_live: false,
  is_simulated: false,
  source: null,
  active_interface: null,
  bpf_filter: 'ip',
  packets_captured: 0,
  bytes_captured: 0,
  packets_dropped: 0,
  events_ingested: 0,
  packet_events_ingested: 0,
  flow_events_ingested: 0,
  flows_completed: 0,
  active_flows: 0,
  packet_events_enabled: true,
  corrupted_packets: 0,
  collector_errors: 0,
  processing_errors: 0,
  last_collector_error: null,
  last_processing_error: null,
  uptime_seconds: 0,
  throughput_pps: 0,
  live_capture_available: true,
  live_capture_unavailable_reason: null,
  live_capture_verified: false,
  allowed_interfaces: null,
  tls: { builtin_handshake_parser: 'available', sni: 'available', ja3: 'available', ja4: 'unsupported', zeek: { available: false } },
  last_pcap: null,
  ...over,
})

export const health = (over: Record<string, unknown> = {}) => ({
  status: 'degraded',
  database: 'connected',
  model_loaded: false,
  detector_state: 'unavailable',
  detector: {
    state: 'unavailable',
    available: false,
    backend: 'kitnet_baseline',
    model: 'kitnet_baseline',
    final_model: false,
    reason: 'No model checkpoint found.',
  },
  ...over,
})
