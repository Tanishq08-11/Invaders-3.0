import { CircleSlash, Database, PlugZap, Radio, RotateCw, WifiOff } from 'lucide-react'
import { cn } from '@/lib/utils'
import { SEVERITY_COLOR, SEVERITY_LABEL, STATUS_COLOR, STATUS_LABEL } from '@/lib/severity'
import type { ConnectionState } from '@/api/queries'
import type { AlertStatus, DataSource, Severity } from '@/types'

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
  replay: { label: 'Replayed data', hint: 'Historical traffic replayed from a dataset - not live capture', color: '#F59E0B' },
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

export function ScoringFailedBadge() {
  return (
    <Pill color="#F59E0B">
      <CircleSlash className="size-3" />
      Scoring failed
    </Pill>
  )
}
