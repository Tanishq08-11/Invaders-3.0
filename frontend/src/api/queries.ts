import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ApiError, isApiConfigured } from './client'
import { getAlert, getAlerts, getDeviceTimeline, getHealth, getMetrics, patchAlert } from './endpoints'
import type { AlertUpdate } from '@/types'

export const keys = {
  alerts: ['alerts'] as const,
  alert: (id: string) => ['alerts', id] as const,
  device: (id: string) => ['devices', id, 'timeline'] as const,
  metrics: ['metrics'] as const,
  health: ['health'] as const,
}

// Do not hammer a backend that is missing, rejecting the request, or answering with a bad contract.
function shouldRetry(count: number, err: unknown): boolean {
  if (count >= 1) return false
  if (!(err instanceof ApiError)) return true
  if (err.kind === 'not_configured' || err.kind === 'invalid_response') return false
  if (err.kind === 'http' && (err.status ?? 500) < 500) return false
  return true
}

const base = { retry: shouldRetry, staleTime: 15_000 }
const poll = (ms: number) => (isApiConfigured ? ms : false)

export const useAlerts = () =>
  useQuery({
    queryKey: keys.alerts,
    queryFn: ({ signal }) => getAlerts(signal),
    enabled: isApiConfigured,
    refetchInterval: poll(30_000),
    ...base,
  })

export const useAlert = (id: string) =>
  useQuery({
    queryKey: keys.alert(id),
    queryFn: ({ signal }) => getAlert(id, signal),
    enabled: isApiConfigured && !!id,
    ...base,
  })

export const useDeviceTimeline = (id: string) =>
  useQuery({
    queryKey: keys.device(id),
    queryFn: ({ signal }) => getDeviceTimeline(id, signal),
    enabled: isApiConfigured && !!id,
    ...base,
  })

export const useMetrics = () =>
  useQuery({
    queryKey: keys.metrics,
    queryFn: ({ signal }) => getMetrics(signal),
    enabled: isApiConfigured,
    refetchInterval: poll(30_000),
    ...base,
  })

export const useHealth = () =>
  useQuery({
    queryKey: keys.health,
    queryFn: ({ signal }) => getHealth(signal),
    enabled: isApiConfigured,
    refetchInterval: poll(15_000),
    ...base,
  })

export function useUpdateAlert(id: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (update: AlertUpdate) => patchAlert(id, update),
    // No optimistic update: the UI only reflects a change the backend has acknowledged.
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.alert(id) })
      void qc.invalidateQueries({ queryKey: keys.alerts })
      void qc.invalidateQueries({ queryKey: keys.metrics })
    },
  })
}

export type ConnectionState = 'not_configured' | 'checking' | 'connected' | 'disconnected'

export function useConnection(): { state: ConnectionState; error: ApiError | null } {
  const q = useHealth()
  if (!isApiConfigured) return { state: 'not_configured', error: null }
  if (q.isSuccess) return { state: 'connected', error: null }
  if (q.isError) return { state: 'disconnected', error: q.error instanceof ApiError ? q.error : null }
  return { state: 'checking', error: null }
}
