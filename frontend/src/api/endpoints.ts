import { z } from 'zod'
import { request } from './client'
import {
  alertDetailSchema,
  alertListSchema,
  alertUpdateSchema,
  collectorActionSchema,
  collectorStatusSchema,
  deviceTimelineSchema,
  eventDetailSchema,
  eventListSchema,
  eventStatsSchema,
  healthSchema,
  interfacesSchema,
  metricsSchema,
  pcapResultSchema,
} from './schemas'
import type {
  Alert,
  AlertDetail,
  AlertUpdate,
  CaptureInterfaces,
  CollectorAction,
  CollectorStatus,
  DeviceTimeline,
  EventList,
  EventStats,
  EventType,
  Health,
  Metrics,
  PcapResult,
  PipelineEventDetail,
} from '@/types'

const enc = encodeURIComponent
const API = '/api/v1'

// POST /api/v1/events belongs to the ingestion team and is intentionally not called from the UI.
// The UI reads the event log (GET /api/v1/events) and drives the collector (ADMIN only).

// Filtering, sorting and paging happen client-side, so fetch the newest 1000 (the backend maximum).
export const getAlerts = (signal?: AbortSignal): Promise<Alert[]> =>
  request(`${API}/alerts?per_page=1000`, { schema: alertListSchema, signal })

export const getAlert = (id: string, signal?: AbortSignal): Promise<AlertDetail> =>
  request(`${API}/alerts/${enc(id)}`, { schema: alertDetailSchema, signal })

export const getDeviceTimeline = (id: string, signal?: AbortSignal): Promise<DeviceTimeline> =>
  request(`${API}/devices/${enc(id)}/timeline`, { schema: deviceTimelineSchema, signal })

export const getMetrics = (signal?: AbortSignal): Promise<Metrics> =>
  request(`${API}/metrics`, { schema: metricsSchema, signal })

export const getHealth = (signal?: AbortSignal): Promise<Health> =>
  request(`${API}/health`, { schema: healthSchema, signal })

/**
 * PROVISIONAL: the backend may answer with the updated alert or with an empty body object.
 * Both are accepted; callers re-fetch the alert afterwards instead of trusting the response.
 */
export const patchAlert = (id: string, update: AlertUpdate): Promise<unknown> =>
  request(`${API}/alerts/${enc(id)}`, {
    method: 'PATCH',
    body: alertUpdateSchema.parse(update),
    schema: z.unknown(),
  })

// ---- Event log ---------------------------------------------------------------------------

export interface EventFilters {
  types?: EventType[]
  source?: string
  detectionStatus?: string
  beforeId?: number | null
  limit?: number
}

export function eventsQueryString(f: EventFilters = {}): string {
  const p = new URLSearchParams()
  if (f.types?.length) p.set('type', f.types.join(','))
  if (f.source) p.set('source', f.source)
  if (f.detectionStatus) p.set('detection_status', f.detectionStatus)
  if (f.beforeId) p.set('before_id', String(f.beforeId))
  p.set('limit', String(f.limit ?? 100))
  return p.toString()
}

export const getEvents = (f: EventFilters, signal?: AbortSignal): Promise<EventList> =>
  request(`${API}/events?${eventsQueryString(f)}`, { schema: eventListSchema, signal })

export const getEvent = (uuid: string, signal?: AbortSignal): Promise<PipelineEventDetail> =>
  request(`${API}/events/${enc(uuid)}`, { schema: eventDetailSchema, signal })

export const getEventStats = (signal?: AbortSignal): Promise<EventStats> =>
  request(`${API}/events/stats`, { schema: eventStatsSchema, signal })

// ---- Network collector -------------------------------------------------------------------

export const getCollectorStatus = (signal?: AbortSignal): Promise<CollectorStatus> =>
  request(`${API}/collector/status`, { schema: collectorStatusSchema, signal })

export const getCaptureInterfaces = (signal?: AbortSignal): Promise<CaptureInterfaces> =>
  request(`${API}/collector/interfaces`, { schema: interfacesSchema, signal })

export interface CollectorStartRequest {
  mode: 'live' | 'simulation'
  interface?: string
  filter?: string
}

export const startCollector = (body: CollectorStartRequest): Promise<CollectorAction> =>
  request(`${API}/collector/start`, { method: 'POST', body, schema: collectorActionSchema })

export const stopCollector = (): Promise<CollectorAction> =>
  request(`${API}/collector/stop`, { method: 'POST', body: {}, schema: collectorActionSchema })

export const stopPcap = (): Promise<CollectorAction> =>
  request(`${API}/collector/pcap/stop`, { method: 'POST', body: {}, schema: collectorActionSchema })

export function analysePcap(file: File, maxPackets?: number, signal?: AbortSignal): Promise<PcapResult> {
  const form = new FormData()
  form.append('file', file)
  if (maxPackets) form.append('max_packets', String(maxPackets))
  // 422 still carries a parse summary (partial results up to the corrupt packet).
  return request(`${API}/collector/pcap`, { method: 'POST', body: form, schema: pcapResultSchema, acceptStatus: [422], signal })
}
