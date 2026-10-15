import { useEffect, useSyncExternalStore } from 'react'
import { useQueryClient, type QueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { apiUrl, isApiConfigured, isCrossOrigin } from './client'
import { keys } from './keys'
import { collectorStatusSchema } from './schemas'

/**
 * Live updates over Server-Sent Events (GET /api/v1/stream/live, SOC roles only).
 *
 * - One EventSource per browser tab, shared by every component (ref-counted), so React
 *   StrictMode double-mounts or several views never open duplicate subscriptions.
 * - Messages are notifications only: they invalidate React Query caches and the views
 *   re-read the REST API. Nothing is rendered from the stream directly, so the same
 *   alert arriving by SSE and by polling can never appear twice, and nothing is invented.
 * - Reconnects with exponential backoff (1 s … 30 s). While the stream is down the
 *   query hooks poll at their normal rate; while it is connected they poll slowly.
 */
export type LiveStatus = 'idle' | 'connecting' | 'connected' | 'reconnecting' | 'unavailable'

export interface LiveMessage {
  id: number
  type: 'hello' | 'event' | 'alert' | 'correlation' | 'collector_status' | string
  ts?: string
  data: Record<string, unknown>
}

type EventSourceLike = Pick<EventSource, 'close' | 'readyState'> & {
  onopen: ((ev: Event) => unknown) | null
  onmessage: ((ev: MessageEvent) => unknown) | null
  onerror: ((ev: Event) => unknown) | null
}
type Factory = (url: string, init: EventSourceInit) => EventSourceLike

const STREAM_PATH = '/api/v1/stream/live'
const CLOSED = 2
const MAX_BACKOFF_MS = 30_000
const FAILURES_BEFORE_UNAVAILABLE = 3

export class LiveStream {
  private es: EventSourceLike | null = null
  private refs = 0
  private status: LiveStatus = 'idle'
  private failures = 0
  private lastId = 0
  private retryTimer: ReturnType<typeof setTimeout> | null = null
  private statusListeners = new Set<() => void>()
  private handlers = new Set<(msg: LiveMessage) => void>()
  private factory: Factory

  constructor(factory?: Factory) {
    this.factory = factory ?? ((url, init) => new EventSource(url, init) as unknown as EventSourceLike)
  }

  getStatus = (): LiveStatus => this.status
  onStatus = (fn: () => void) => {
    this.statusListeners.add(fn)
    return () => {
      this.statusListeners.delete(fn)
    }
  }
  /** Number of open EventSource connections (0 or 1). */
  get connections() {
    return this.es ? 1 : 0
  }

  subscribe(handler: (msg: LiveMessage) => void) {
    this.handlers.add(handler)
    return () => {
      this.handlers.delete(handler)
    }
  }

  /** Take a reference; the first one connects. Returns the release function. */
  acquire(): () => void {
    this.refs += 1
    if (this.refs === 1) this.connect()
    let released = false
    return () => {
      if (released) return
      released = true
      this.refs -= 1
      if (this.refs === 0) this.disconnect()
    }
  }

  private setStatus(s: LiveStatus) {
    if (s === this.status) return
    this.status = s
    this.statusListeners.forEach((fn) => fn())
  }

  private connect() {
    if (this.es || !isApiConfigured) return
    this.setStatus(this.failures ? 'reconnecting' : 'connecting')
    let es: EventSourceLike
    try {
      es = this.factory(apiUrl(STREAM_PATH), { withCredentials: isCrossOrigin })
    } catch {
      this.scheduleRetry()
      return
    }
    this.es = es
    es.onopen = () => {
      this.failures = 0
      this.setStatus('connected')
    }
    es.onmessage = (ev: MessageEvent) => this.handleMessage(ev)
    es.onerror = () => {
      // HTTP errors (401/403/503) close the stream; network errors leave it CONNECTING and
      // the browser retries. Either way, after repeated failures take over with our backoff.
      this.failures += 1
      if (es.readyState === CLOSED || this.failures >= FAILURES_BEFORE_UNAVAILABLE) {
        es.close()
        if (this.es === es) this.es = null
        this.scheduleRetry()
      } else {
        this.setStatus('reconnecting')
      }
    }
  }

  private scheduleRetry() {
    if (this.refs === 0) return
    this.setStatus(this.failures >= FAILURES_BEFORE_UNAVAILABLE ? 'unavailable' : 'reconnecting')
    const delay = Math.min(MAX_BACKOFF_MS, 1000 * 2 ** Math.max(0, this.failures - 1))
    if (this.retryTimer) clearTimeout(this.retryTimer)
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null
      this.connect()
    }, delay)
  }

  private disconnect() {
    if (this.retryTimer) clearTimeout(this.retryTimer)
    this.retryTimer = null
    this.es?.close()
    this.es = null
    this.failures = 0
    this.setStatus('idle')
  }

  private handleMessage(ev: MessageEvent) {
    let msg: LiveMessage
    try {
      msg = JSON.parse(String(ev.data)) as LiveMessage
    } catch {
      return
    }
    if (typeof msg !== 'object' || msg === null || typeof msg.type !== 'string') return
    if (msg.type === 'hello') {
      this.lastId = 0 // the server's sequence restarts with every connection
    } else if (typeof msg.id === 'number') {
      if (msg.id <= this.lastId) return // replayed / duplicate delivery
      this.lastId = msg.id
    }
    this.handlers.forEach((h) => h(msg))
  }

  /** Test helper. */
  reset(factory?: Factory) {
    this.disconnect()
    this.refs = 0
    this.lastId = 0
    this.handlers.clear()
    if (factory) this.factory = factory
  }
}

export const liveStream = new LiveStream()

export function useLiveStatus(): LiveStatus {
  return useSyncExternalStore(liveStream.onStatus, liveStream.getStatus, liveStream.getStatus)
}

/** Maps stream messages to cache invalidation, batched so bursts cause one refetch per view. */
export function createLiveHandler(qc: QueryClient, opts: { notify?: (title: string, body: string) => void } = {}) {
  const pending = new Set<string>()
  const seenAlerts = new Set<string>()
  let timer: ReturnType<typeof setTimeout> | null = null
  const KEYS: Record<string, readonly unknown[]> = {
    alerts: keys.alerts,
    metrics: keys.metrics,
    events: keys.events,
    collector: keys.collector,
    health: keys.health,
  }
  const flush = () => {
    timer = null
    pending.forEach((k) => void qc.invalidateQueries({ queryKey: KEYS[k] }))
    pending.clear()
  }
  const mark = (...names: string[]) => {
    names.forEach((n) => pending.add(n))
    if (!timer) timer = setTimeout(flush, 750)
  }

  const handler = (msg: LiveMessage) => {
    switch (msg.type) {
      case 'hello':
        mark('collector', 'health')
        break
      case 'collector_status': {
        const parsed = collectorStatusSchema.safeParse(msg.data)
        if (parsed.success) qc.setQueryData(keys.collectorStatus, parsed.data)
        else mark('collector')
        break
      }
      case 'event':
        mark('events', 'metrics')
        break
      case 'correlation':
        mark('events')
        break
      case 'alert': {
        mark('alerts', 'metrics', 'events')
        const id = String((msg.data as { id?: unknown }).id ?? '')
        if (id && !seenAlerts.has(id)) {
          seenAlerts.add(id)
          const sev = String((msg.data as { severity?: unknown }).severity ?? '').toLowerCase()
          opts.notify?.('New alert', `${sev ? sev.toUpperCase() + ' · ' : ''}${String((msg.data as { src_ip?: unknown }).src_ip ?? '')}`)
        }
        break
      }
    }
  }
  return { handler, flush, seenAlerts }
}

/** Mount once per SOC session (SocShell). */
export function useLiveUpdates() {
  const qc = useQueryClient()
  useEffect(() => {
    if (!isApiConfigured) return
    const { handler } = createLiveHandler(qc, { notify: (title, body) => toast.info(title, { description: body }) })
    const unsubscribe = liveStream.subscribe(handler)
    const release = liveStream.acquire()
    return () => {
      unsubscribe()
      release()
    }
  }, [qc])
}
