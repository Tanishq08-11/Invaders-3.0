import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ApiError, isApiConfigured } from './client'
import {
  analysePcap,
  getAlert,
  getAlerts,
  getCaptureInterfaces,
  getCollectorStatus,
  getDeviceTimeline,
  getEvent,
  getEventStats,
  getEvents,
  getHealth,
  getMetrics,
  patchAlert,
  startCollector,
  stopCollector,
  stopPcap,
  type CollectorStartRequest,
  type EventFilters,
} from './endpoints'
import { keys } from './keys'
import { useLiveStatus, type LiveStatus } from './live'
import type { AlertUpdate, CollectorAction } from '@/types'

export { keys }

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

/**
 * Polling is the fallback for live updates: while the SSE stream is connected, views are
 * refreshed by stream notifications and polling slows down; otherwise it runs at `fast`.
 */
export function pollIntervalFor(live: LiveStatus, fast: number, slow: number): number {
  return live === 'connected' ? slow : fast
}

function useAdaptivePoll(fast: number, slow: number) {
  return poll(pollIntervalFor(useLiveStatus(), fast, slow))
}

export const useAlerts = () => {
  const interval = useAdaptivePoll(30_000, 120_000)
  return useQuery({
    queryKey: keys.alerts,
    queryFn: ({ signal }) => getAlerts(signal),
    enabled: isApiConfigured,
    refetchInterval: interval,
    ...base,
  })
}

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

export const useMetrics = () => {
  const interval = useAdaptivePoll(30_000, 120_000)
  return useQuery({
    queryKey: keys.metrics,
    queryFn: ({ signal }) => getMetrics(signal),
    enabled: isApiConfigured,
    refetchInterval: interval,
    ...base,
  })
}

export const useHealth = () =>
  useQuery({
    queryKey: keys.health,
    queryFn: ({ signal }) => getHealth(signal),
    enabled: isApiConfigured,
    refetchInterval: poll(15_000),
    ...base,
  })

export const useEvents = (filters: EventFilters) => {
  const interval = useAdaptivePoll(15_000, 60_000)
  return useQuery({
    queryKey: keys.eventList(filters),
    queryFn: ({ signal }) => getEvents(filters, signal),
    enabled: isApiConfigured,
    refetchInterval: filters.beforeId ? false : interval, // older pages do not change
    placeholderData: keepPreviousData,
    ...base,
  })
}

export const useEvent = (uuid: string | null) =>
  useQuery({
    queryKey: keys.event(uuid ?? ''),
    queryFn: ({ signal }) => getEvent(uuid as string, signal),
    enabled: isApiConfigured && !!uuid,
    ...base,
  })

export const useEventStats = () => {
  const interval = useAdaptivePoll(15_000, 60_000)
  return useQuery({
    queryKey: keys.eventStats,
    queryFn: ({ signal }) => getEventStats(signal),
    enabled: isApiConfigured,
    refetchInterval: interval,
    ...base,
  })
}

export const useCollectorStatus = () => {
  const interval = useAdaptivePoll(5_000, 30_000)
  return useQuery({
    queryKey: keys.collectorStatus,
    queryFn: ({ signal }) => getCollectorStatus(signal),
    enabled: isApiConfigured,
    refetchInterval: interval,
    ...base,
    staleTime: 2_000,
  })
}

export const useCaptureInterfaces = (enabled: boolean) =>
  useQuery({
    queryKey: keys.interfaces,
    queryFn: ({ signal }) => getCaptureInterfaces(signal),
    enabled: isApiConfigured && enabled,
    ...base,
  })

function useCollectorMutation<TArgs, TResult>(fn: (args: TArgs) => Promise<TResult>) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: fn,
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: keys.collector })
      void qc.invalidateQueries({ queryKey: keys.health })
      void qc.invalidateQueries({ queryKey: keys.events })
      void qc.invalidateQueries({ queryKey: keys.metrics })
    },
  })
}

export const useStartCollector = () => useCollectorMutation((body: CollectorStartRequest) => startCollector(body))
export const useStopCollector = () => useCollectorMutation<void, CollectorAction>(() => stopCollector())
export const useStopPcap = () => useCollectorMutation<void, CollectorAction>(() => stopPcap())
export const useAnalysePcap = () =>
  useCollectorMutation(({ file, maxPackets, signal }: { file: File; maxPackets?: number; signal?: AbortSignal }) =>
    analysePcap(file, maxPackets, signal),
  )

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
