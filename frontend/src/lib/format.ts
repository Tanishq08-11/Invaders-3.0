const UNITS = ['B', 'KB', 'MB', 'GB', 'TB']

export function formatBytes(n?: number | null): string {
  if (n == null || !Number.isFinite(n)) return '—'
  let v = Math.abs(n)
  let i = 0
  while (v >= 1024 && i < UNITS.length - 1) {
    v /= 1024
    i++
  }
  return `${v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${UNITS[i]}`
}

export function formatNumber(n?: number | null): string {
  return n == null || !Number.isFinite(n) ? '—' : new Intl.NumberFormat().format(n)
}

export function formatDateTime(iso?: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' })
}

export function formatTime(iso?: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime())
    ? iso
    : d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
}

export function formatDuration(s?: number | null): string {
  if (s == null || !Number.isFinite(s)) return '—'
  if (s < 1) return `${Math.round(s * 1000)} ms`
  if (s < 60) return `${s.toFixed(1)} s`
  const m = Math.floor(s / 60)
  return m < 60 ? `${m}m ${Math.round(s % 60)}s` : `${Math.floor(m / 60)}h ${m % 60}m`
}

export const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 } as const

export const labelize = (s: string) => s.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())

/** Human-friendly age of a timestamp relative to `now` (ms). Falls back to the raw string if unparsable. */
export function formatRelative(iso?: string | null, now: number = Date.now()): string {
  if (!iso) return '—'
  const t = new Date(iso).getTime()
  if (Number.isNaN(t)) return iso
  const s = Math.round((now - t) / 1000)
  if (s < 0) return 'just now' // small clock skew between backend and browser
  if (s < 45) return 'just now'
  const m = Math.round(s / 60)
  if (m < 60) return `${m} min ago`
  const h = Math.round(m / 60)
  if (h < 24) return `${h} h ago`
  const d = Math.round(h / 24)
  return d < 7 ? `${d} d ago` : new Date(t).toLocaleDateString()
}
