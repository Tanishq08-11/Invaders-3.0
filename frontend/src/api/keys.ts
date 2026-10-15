import type { EventFilters } from './endpoints'

/** React Query keys, shared by query hooks and the live-update (SSE) invalidation. */
export const keys = {
  alerts: ['alerts'] as const,
  alert: (id: string) => ['alerts', id] as const,
  device: (id: string) => ['devices', id, 'timeline'] as const,
  metrics: ['metrics'] as const,
  health: ['health'] as const,
  events: ['events'] as const,
  eventList: (f: EventFilters) => ['events', 'list', f] as const,
  event: (uuid: string) => ['events', 'detail', uuid] as const,
  eventStats: ['events', 'stats'] as const,
  collector: ['collector'] as const,
  collectorStatus: ['collector', 'status'] as const,
  interfaces: ['collector', 'interfaces'] as const,
}
