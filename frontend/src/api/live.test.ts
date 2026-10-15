import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { QueryClient } from '@tanstack/react-query'
import { createLiveHandler, LiveStream, type LiveMessage } from './live'
import { keys } from './keys'
import { pollIntervalFor } from './queries'
import { collectorStatus } from '@/test/utils'

class FakeES {
  static instances: FakeES[] = []
  readyState = 0
  closed = false
  onopen: ((ev: Event) => unknown) | null = null
  onmessage: ((ev: MessageEvent) => unknown) | null = null
  onerror: ((ev: Event) => unknown) | null = null
  url: string
  init: EventSourceInit
  constructor(url: string, init: EventSourceInit) {
    this.url = url
    this.init = init
    FakeES.instances.push(this)
  }
  close() {
    this.closed = true
    this.readyState = 2
  }
  open() {
    this.readyState = 1
    this.onopen?.(new Event('open'))
  }
  send(msg: Partial<LiveMessage>) {
    this.onmessage?.(new MessageEvent('message', { data: JSON.stringify(msg) }))
  }
  fail(closed: boolean) {
    this.readyState = closed ? 2 : 0
    this.onerror?.(new Event('error'))
  }
}

const open = () => FakeES.instances.filter((e) => !e.closed)
let stream: LiveStream

beforeEach(() => {
  FakeES.instances = []
  vi.useFakeTimers()
  stream = new LiveStream((url, init) => new FakeES(url, init))
})
afterEach(() => {
  stream.reset()
  vi.useRealTimers()
})

describe('LiveStream (SSE)', () => {
  it('shares one EventSource between subscribers and closes it when the last one leaves', () => {
    const r1 = stream.acquire()
    const r2 = stream.acquire() // e.g. StrictMode double mount / second view
    expect(FakeES.instances).toHaveLength(1)
    expect(FakeES.instances[0].url).toBe('/api/v1/stream/live')
    r1()
    r1() // releasing twice is harmless
    expect(open()).toHaveLength(1)
    r2()
    expect(open()).toHaveLength(0)
    expect(stream.getStatus()).toBe('idle')
  })

  it('reports connected and delivers parsed messages', () => {
    const got: LiveMessage[] = []
    stream.subscribe((m) => got.push(m))
    stream.acquire()
    FakeES.instances[0].open()
    expect(stream.getStatus()).toBe('connected')
    FakeES.instances[0].send({ id: 0, type: 'hello', data: {} })
    FakeES.instances[0].send({ id: 1, type: 'alert', data: { id: 7 } })
    expect(got.map((m) => m.type)).toEqual(['hello', 'alert'])
  })

  it('drops duplicate or replayed message ids', () => {
    const got: number[] = []
    stream.subscribe((m) => got.push(m.id))
    stream.acquire()
    const es = FakeES.instances[0]
    es.send({ id: 0, type: 'hello', data: {} })
    es.send({ id: 1, type: 'event', data: {} })
    es.send({ id: 1, type: 'event', data: {} })
    es.send({ id: 2, type: 'event', data: {} })
    expect(got).toEqual([0, 1, 2])
  })

  it('reconnects with backoff after the server closes the stream, never opening two at once', () => {
    stream.acquire()
    FakeES.instances[0].fail(true) // e.g. 503 - stream closed by the server
    expect(stream.getStatus()).toBe('reconnecting')
    expect(open()).toHaveLength(0)
    vi.advanceTimersByTime(1000)
    expect(FakeES.instances).toHaveLength(2)
    expect(open()).toHaveLength(1)
    FakeES.instances[1].fail(true)
    FakeES.instances.length = 2
    vi.advanceTimersByTime(1999)
    expect(FakeES.instances).toHaveLength(2) // backoff doubled to 2 s
    vi.advanceTimersByTime(1)
    expect(open()).toHaveLength(1)
    FakeES.instances[2].open()
    expect(stream.getStatus()).toBe('connected')
  })

  it('falls back to "unavailable" (polling) after repeated failures and stops retrying once released', () => {
    const release = stream.acquire()
    for (let i = 0; i < 3; i++) {
      FakeES.instances[FakeES.instances.length - 1].fail(true)
      vi.advanceTimersByTime(30_000)
    }
    FakeES.instances[FakeES.instances.length - 1].fail(true)
    expect(stream.getStatus()).toBe('unavailable')
    release()
    const count = FakeES.instances.length
    vi.advanceTimersByTime(120_000)
    expect(FakeES.instances).toHaveLength(count)
  })
})

describe('live message handling', () => {
  it('invalidates the affected views once per burst and toasts each alert only once', () => {
    const qc = new QueryClient()
    const spy = vi.spyOn(qc, 'invalidateQueries')
    const notify = vi.fn()
    const { handler } = createLiveHandler(qc, { notify })
    handler({ id: 1, type: 'alert', data: { id: 5, severity: 'high', src_ip: '10.0.0.5' } })
    handler({ id: 2, type: 'alert', data: { id: 5, severity: 'high', src_ip: '10.0.0.5' } }) // same alert again
    handler({ id: 3, type: 'event', data: {} })
    expect(spy).not.toHaveBeenCalled() // batched
    vi.advanceTimersByTime(800)
    const invalidated = spy.mock.calls.map((c) => JSON.stringify(c[0]?.queryKey))
    expect(invalidated).toEqual(expect.arrayContaining([JSON.stringify(keys.alerts), JSON.stringify(keys.events), JSON.stringify(keys.metrics)]))
    expect(new Set(invalidated).size).toBe(invalidated.length) // each view refreshed once
    expect(notify).toHaveBeenCalledTimes(1)
  })

  it('writes collector status from the stream straight into the cache', () => {
    const qc = new QueryClient()
    const { handler } = createLiveHandler(qc)
    handler({ id: 1, type: 'collector_status', data: collectorStatus({ mode: 'simulation', is_running: true, is_simulated: true }) })
    expect(qc.getQueryData(keys.collectorStatus)).toMatchObject({ mode: 'simulation', is_simulated: true })
  })

  it('polls slowly only while the stream is connected', () => {
    expect(pollIntervalFor('connected', 5000, 30000)).toBe(30000)
    for (const s of ['idle', 'connecting', 'reconnecting', 'unavailable'] as const) expect(pollIntervalFor(s, 5000, 30000)).toBe(5000)
  })
})
