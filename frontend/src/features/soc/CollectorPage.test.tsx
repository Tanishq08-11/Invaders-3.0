import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react'
import { CollectorPage } from './CollectorPage'
import { EventLogPage } from './EventLogPage'
import { collectorStatus, health, mockBackend, renderWithProviders, user } from '@/test/utils'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const interfaces = {
  interfaces: [
    { name: 'Ethernet', description: 'Realtek PCIe GbE', ips: ['10.0.0.9'], allowed: true },
    { name: 'Wi-Fi', description: 'Wireless', ips: [], allowed: false },
  ],
  live_capture_available: true,
}

describe('CollectorPage', () => {
  it('labels simulation unmistakably and never as live', async () => {
    mockBackend([
      { path: '/api/v1/auth/me', body: user('SECURITY_ANALYST') },
      { path: '/api/v1/collector/status', body: collectorStatus({ mode: 'simulation', is_running: true, is_simulated: true, source: 'simulation', packets_captured: 12 }) },
      { path: '/api/v1/health', body: health() },
    ])
    renderWithProviders(<CollectorPage />)
    expect(await screen.findByText(/Simulation mode — synthetic packets, not real network traffic/)).toBeTruthy()
    expect(screen.getByText('SIMULATION')).toBeTruthy()
    expect(screen.queryByText('LIVE capture')).toBeNull()
    expect(screen.getByText('12')).toBeTruthy()
  })

  it('shows the detector as unavailable and read-only controls for analysts', async () => {
    mockBackend([
      { path: '/api/v1/auth/me', body: user('SECURITY_ANALYST') },
      { path: '/api/v1/collector/status', body: collectorStatus() },
      { path: '/api/v1/health', body: health() },
    ])
    renderWithProviders(<CollectorPage />)
    // both the capture controls and the PCAP panel are read-only
    expect(await screen.findAllByText(/requires an administrator/)).toHaveLength(2)
    expect(screen.queryByRole('button', { name: /Start live capture/ })).toBeNull()
    expect(await screen.findByText(/none are scored: No model checkpoint found/)).toBeTruthy()
  })

  it('sends a live start for the explicitly selected interface', async () => {
    const { calls } = mockBackend([
      { path: '/api/v1/auth/me', body: user('ADMIN') },
      { path: '/api/v1/collector/status', body: collectorStatus() },
      { path: '/api/v1/collector/interfaces', body: interfaces },
      { path: '/api/v1/health', body: health() },
      { method: 'POST', path: '/api/v1/collector/start', body: { status: 'started', mode: 'live', interface: 'Ethernet' } },
    ])
    renderWithProviders(<CollectorPage />)
    const startBtn = await screen.findByRole('button', { name: /Start live capture/ })
    await waitFor(() => expect((startBtn as HTMLButtonElement).disabled).toBe(false))
    fireEvent.click(startBtn)
    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true))
    const post = calls.find((c) => c.method === 'POST')!
    expect(post.url).toBe('/api/v1/collector/start')
    expect(JSON.parse(String(post.init?.body))).toEqual({ mode: 'live', interface: 'Ethernet', filter: 'ip' })
    // unauthorised interfaces cannot be selected
    const opt = screen.getByRole('option', { name: /Wi-Fi/ }) as HTMLOptionElement
    expect(opt.disabled).toBe(true)
  })

  it('disables live capture when the host cannot capture and shows the backend error on failure', async () => {
    mockBackend([
      { path: '/api/v1/auth/me', body: user('ADMIN') },
      { path: '/api/v1/collector/status', body: collectorStatus({ live_capture_available: false, live_capture_unavailable_reason: 'No packet-capture provider' }) },
      { path: '/api/v1/collector/interfaces', body: interfaces },
      { path: '/api/v1/health', body: health() },
      { method: 'POST', path: '/api/v1/collector/start', status: 503, body: { status: 'error', error: 'Failed to start simulation worker' } },
    ])
    renderWithProviders(<CollectorPage />)
    const live = await screen.findByRole('button', { name: /Start live capture/ })
    expect((live as HTMLButtonElement).disabled).toBe(true)
    expect(screen.getByText(/unavailable on this host: No packet-capture provider/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: /Start simulation/ }))
    expect(await screen.findByText(/Start failed: Failed to start simulation worker/)).toBeTruthy()
  })

  it('shows a backend outage instead of empty counters', async () => {
    mockBackend([
      { path: '/api/v1/auth/me', body: user('ADMIN') },
      { path: '/api/v1/collector/status', status: 500, body: { detail: 'boom' } },
      { path: '/api/v1/health', body: health() },
    ])
    renderWithProviders(<CollectorPage />)
    // one retry on 5xx (shouldRetry) happens before the error is shown
    expect(await screen.findByText(/Backend error \(500\)/, undefined, { timeout: 5000 })).toBeTruthy()
    expect(screen.queryByText('Packets observed')).toBeNull()
  })

  it('provides a stop button for PCAP analysis and sends stop request', async () => {
    const { calls } = mockBackend([
      { path: '/api/v1/auth/me', body: user('ADMIN') },
      { path: '/api/v1/collector/status', body: collectorStatus({ is_pcap_processing: true }) },
      { path: '/api/v1/collector/interfaces', body: interfaces },
      { path: '/api/v1/health', body: health() },
      { method: 'POST', path: '/api/v1/collector/pcap/stop', body: { status: 'stopping', message: 'PCAP analysis stop requested.' } },
    ])
    renderWithProviders(<CollectorPage />)
    const stopBtn = await screen.findByRole('button', { name: /Stop PCAP analysis/i })
    expect((stopBtn as HTMLButtonElement).disabled).toBe(false)
    fireEvent.click(stopBtn)
    await waitFor(() => expect(calls.some((c) => c.url === '/api/v1/collector/pcap/stop')).toBe(true))
  })
})

describe('EventLogPage', () => {
  it('renders events loaded from the backend with their detection status', async () => {
    mockBackend([
      { path: '/api/v1/auth/me', body: user('SECURITY_ANALYST') },
      { path: '/api/v1/events/stats', body: { by_type: { application_activity: 1 }, by_source: {}, by_detection_status: { unavailable: 1 }, correlations: 0 } },
      {
        path: '/api/v1/events',
        body: {
          items: [
            {
              id: 1, event_uuid: 'EVT-1', event_type: 'application_activity', source: 'application', data_source: 'unknown',
              timestamp: '2026-10-15T10:00:00+00:00', detection_status: 'not_applicable', user_id: 3,
              user: { username: 'eng01', display_name: 'Eng', department: 'Engineering' }, action: 'upload', outcome: 'success', src_ip: '10.0.0.5',
            },
            {
              id: 2, event_uuid: 'EVT-2', event_type: 'network_record', source: 'api', data_source: 'unknown',
              timestamp: '2026-10-15T10:00:01+00:00', detection_status: 'unavailable', src_ip: '10.0.0.5', dst_ip: '1.1.1.1', dst_port: 443, protocol: 'TCP',
              anomaly_score: null,
            },
          ],
          next_before_id: null,
        },
      },
    ])
    renderWithProviders(<EventLogPage />)
    expect(await screen.findByText('eng01 · upload success')).toBeTruthy()
    expect(screen.getByText('AI unavailable')).toBeTruthy() // not shown as "normal"
    expect(screen.getByText('Context only')).toBeTruthy()
  })
})
