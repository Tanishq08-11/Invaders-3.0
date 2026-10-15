import { z } from 'zod'
import { request } from './client'
import {
  alertDetailSchema,
  alertListSchema,
  alertUpdateSchema,
  deviceTimelineSchema,
  healthSchema,
  metricsSchema,
} from './schemas'
import type { Alert, AlertDetail, AlertUpdate, DeviceTimeline, Health, Metrics } from '@/types'

const enc = encodeURIComponent
const API = '/api/v1'

// POST /api/v1/events belongs to the ingestion team and is intentionally not called from the UI.

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
