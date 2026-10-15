import { CircleSlash, Database, PlugZap, Radio, RotateCw, WifiOff } from 'lucide-react'
import { cn } from '@/lib/utils'
import { SEVERITY_COLOR, SEVERITY_LABEL, STATUS_COLOR, STATUS_LABEL } from '@/lib/severity'
import type { ConnectionState } from '@/api/queries'
import type { LiveStatus } from '@/api/live'
import { EVENT_TYPE_LABEL } from '@/lib/events'
import type { AlertStatus, CollectorMode, DataSource, EventType, Severity } from '@/types'

function Pill({ color, children, className }: { color: string; children: React.ReactNode; className?: string }) {
  return (
    <span
      className={cn('inline-flex items-center gap-1.5 whitespace-nowrap rounded-md border px-2 py-0.5 text-xs font-medium', className)}
      style={{ color, borderColor: `${color}55`, backgroundColor: `${color}14` }}
    >
      {children}
    </span>
  )
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Pill color={SEVERITY_COLOR[severity]}>
      <span className="size-1.5 rounded-full" style={{ backgroundColor: SEVERITY_COLOR[severity] }} />
      {SEVERITY_LABEL[severity]}
    </Pill>
  )
}

export function StatusBadge({ status }: { status: AlertStatus }) {
  return <Pill color={STATUS_COLOR[status]}>{STATUS_LABEL[status]}</Pill>
}

const SOURCE_META: Record<DataSource, { label: string; hint: string; color: string }> = {
  live: { label: 'Live capture', hint: 'Events observed from a live capture', color: '#16A34A' },
  simulation: { label: 'SIMULATED traffic', hint: 'Synthetic packets from the collector simulator - not real network traffic', color: '#C026D3' },
  replay: { label: 'Replayed data', hint: 'Historical traffic replayed from a dataset - not live capture', color: '#F59E0B' },
  pcap: { label: 'Offline PCAP', hint: 'Packets read from an uploaded capture file - not live capture', color: '#0891B2' },
  unknown: { label: 'Source not reported', hint: 'The backend did not state whether data is live or replayed', color: '#64748B' },
}

/** Always distinguishes replayed historical traffic from live capture. */
export function DataSourceBadge({ source }: { source?: DataSource | null }) {
  const meta = SOURCE_META[source ?? 'unknown']
  return (
    <span title={meta.hint}>
      <Pill color={meta.color}>
        <Database className="size-3" />
        {meta.label}
      </Pill>
    </span>
  )
}

const CONN_META: Record<ConnectionState, { label: string; color: string; Icon: typeof Radio }> = {
  connected: { label: 'Backend connected', color: '#16A34A', Icon: Radio },
  checking: { label: 'Checking backend…', color: '#64748B', Icon: RotateCw },
  disconnected: { label: 'Backend disconnected', color: '#DC2626', Icon: WifiOff },
  not_configured: { label: 'Awaiting backend connection', color: '#F59E0B', Icon: PlugZap },
}

export function ConnectionBadge({ state }: { state: ConnectionState }) {
  const { label, color, Icon } = CONN_META[state]
  return (
    <Pill color={color}>
      <Icon className={cn('size-3', state === 'checking' && 'animate-spin')} />
      {label}
    </Pill>
  )
}

const MODE_META: Record<CollectorMode, { label: string; color: string; hint: string }> = {
  stopped: { label: 'Stopped', color: '#64748B', hint: 'The collector is not running' },
  starting: { label: 'Starting…', color: '#0284C7', hint: 'Waiting for the capture socket to open' },
  live: { label: 'LIVE capture', color: '#16A34A', hint: 'Real packets are being observed on the selected interface' },
  simulation: { label: 'SIMULATION', color: '#C026D3', hint: 'Synthetic packets - this is not real network traffic' },
  failed: { label: 'Failed', color: '#DC2626', hint: 'Capture could not start or stopped unexpectedly' },
}

/** Collector operating mode exactly as the backend reports it. */
export function CollectorModeBadge({ mode }: { mode: CollectorMode }) {
  const m = MODE_META[mode]
  return (
    <span title={m.hint}>
      <Pill color={m.color}>
        {mode === 'live' && <span className="size-1.5 animate-pulse rounded-full" style={{ backgroundColor: m.color }} />}
        {m.label}
      </Pill>
    </span>
  )
}

const DETECTION_META: Record<string, { label: string; color: string; hint: string }> = {
  scored: { label: 'Scored', color: '#16A34A', hint: 'The detector evaluated this event' },
  pending: { label: 'Pending', color: '#0284C7', hint: 'Waiting for the detector' },
  unavailable: { label: 'AI unavailable', color: '#F59E0B', hint: 'No detector was loaded - the event was stored without a score' },
  unsupported: { label: 'Not model input', color: '#64748B', hint: 'The loaded detector does not accept this event type' },
  failed: { label: 'Scoring failed', color: '#DC2626', hint: 'The detector raised an error - no score was assigned' },
  not_applicable: { label: 'Context only', color: '#64748B', hint: 'Application evidence is never used as model input' },
}

/** Never shows "normal/safe" for an event the detector did not score. */
export function DetectionStatusBadge({ status }: { status: string }) {
  const m = DETECTION_META[status] ?? { label: status, color: '#64748B', hint: '' }
  return (
    <span title={m.hint}>
      <Pill color={m.color}>{m.label}</Pill>
    </span>
  )
}

export function EventTypeBadge({ type }: { type: EventType }) {
  const color = type === 'application_activity' ? '#7C3AED' : type === 'network_flow' ? '#0078D4' : '#475569'
  return <Pill color={color}>{EVENT_TYPE_LABEL[type]}</Pill>
}

const LIVE_META: Record<LiveStatus, { label: string; color: string; hint: string }> = {
  idle: { label: 'Polling', color: '#64748B', hint: 'Live updates are not connected; views refresh periodically' },
  connecting: { label: 'Connecting…', color: '#0284C7', hint: 'Opening the live update stream' },
  connected: { label: 'Live updates', color: '#16A34A', hint: 'Receiving server-sent events' },
  reconnecting: { label: 'Reconnecting…', color: '#F59E0B', hint: 'Live updates dropped; retrying. Views keep polling meanwhile' },
  unavailable: { label: 'Polling (stream unavailable)', color: '#F59E0B', hint: 'The live stream could not be reached; views refresh periodically' },
}

export function LiveStatusBadge({ status }: { status: LiveStatus }) {
  const m = LIVE_META[status]
  return (
    <span title={m.hint}>
      <Pill color={m.color}>{m.label}</Pill>
    </span>
  )
}

export function ScoringFailedBadge() {
  return (
    <Pill color="#F59E0B">
      <CircleSlash className="size-3" />
      Scoring failed
    </Pill>
  )
}
