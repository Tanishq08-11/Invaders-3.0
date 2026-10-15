import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ComposedChart,
  Line,
  ReferenceDot,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { useRevealOnce } from '@/hooks/useRevealOnce'
import { formatBytes, formatDateTime, formatTime } from '@/lib/format'
import { SEVERITY_COLOR, SEVERITY_LABEL } from '@/lib/severity'
import type { RiskContribution, Severity } from '@/types'

const AXIS = { stroke: '#64748B', fontSize: 11, tickLine: false, axisLine: false } as const
const GRID = '#DCE8F5'
const TOOLTIP = {
  contentStyle: {
    background: '#FFFFFF',
    border: '1px solid #DCE8F5',
    boxShadow: '0 10px 28px -12px rgba(0,90,158,0.3)',
    borderRadius: 8,
    fontSize: 12,
    color: '#102A43',
  },
  labelStyle: { color: '#64748B' },
  cursor: { stroke: '#0078D4', strokeOpacity: 0.3 },
} as const

interface TrendPoint {
  timestamp: string
  bytes_out?: number | null
}

/** Outbound bytes over time. Used on Overview (all traffic) and Device Investigation. */
export function TrafficAreaChart({
  data,
  baseline,
  height = 260,
}: {
  data: TrendPoint[]
  baseline?: number | null
  height?: number
}) {
  const rows = data.filter((d) => d.bytes_out != null)
  const reveal = useRevealOnce()
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={rows} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
        <defs>
          <linearGradient id="trafficFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#0078D4" stopOpacity={0.28} />
            <stop offset="100%" stopColor="#0078D4" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke={GRID} strokeDasharray="3 3" vertical={false} />
        <XAxis dataKey="timestamp" tickFormatter={formatTime} {...AXIS} minTickGap={32} />
        <YAxis tickFormatter={(v: number) => formatBytes(v)} width={64} {...AXIS} />
        <Tooltip
          {...TOOLTIP}
          labelFormatter={(l) => formatDateTime(String(l))}
          formatter={(v) => [formatBytes(Number(v)), 'Outbound']}
        />
        {baseline != null && (
          <ReferenceLine
            y={baseline}
            stroke="#F59E0B"
            strokeDasharray="5 4"
            label={{ value: 'Baseline avg', fill: '#F59E0B', fontSize: 11, position: 'insideTopRight' }}
          />
        )}
        <Area type="monotone" dataKey="bytes_out" stroke="#0078D4" strokeWidth={2} fill="url(#trafficFill)" isAnimationActive={reveal} animationDuration={700} animationEasing="ease-out" />
      </AreaChart>
    </ResponsiveContainer>
  )
}

export function SeverityBarChart({ data }: { data: { severity: Severity; count: number }[] }) {
  return (
    <ResponsiveContainer width="100%" height={Math.max(160, data.length * 44)}>
      <BarChart data={data} layout="vertical" margin={{ left: 8, right: 16 }}>
        <XAxis type="number" hide allowDecimals={false} />
        <YAxis type="category" dataKey="severity" tickFormatter={(s: Severity) => SEVERITY_LABEL[s]} width={64} {...AXIS} />
        <Tooltip {...TOOLTIP} cursor={{ fill: '#0078D40D' }} formatter={(v) => [v, 'Alerts']} labelFormatter={(s) => SEVERITY_LABEL[s as Severity]} />
        <Bar dataKey="count" radius={[0, 6, 6, 0]} barSize={18} label={{ position: 'right', fill: '#102A43', fontSize: 12 }}>
          {data.map((d) => (
            <Cell key={d.severity} fill={SEVERITY_COLOR[d.severity]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

/** Per-signal contribution to the risk score, exactly as supplied by the backend. */
export function ContributionChart({ data }: { data: RiskContribution[] }) {
  const rows = data.map((d) => ({ name: d.label || d.signal, value: d.contribution }))
  return (
    <ResponsiveContainer width="100%" height={Math.max(140, rows.length * 48)}>
      <BarChart data={rows} layout="vertical" margin={{ left: 8, right: 24 }}>
        <CartesianGrid stroke={GRID} strokeDasharray="3 3" horizontal={false} />
        <XAxis type="number" {...AXIS} />
        <YAxis type="category" dataKey="name" width={150} {...AXIS} />
        <Tooltip {...TOOLTIP} cursor={{ fill: '#0078D40D' }} formatter={(v) => [v, 'Contribution']} />
        <Bar dataKey="value" fill="#2563EB" radius={[0, 6, 6, 0]} barSize={16} label={{ position: 'right', fill: '#102A43', fontSize: 11 }} />
      </BarChart>
    </ResponsiveContainer>
  )
}

interface FlowPoint {
  timestamp: string
  bytes_out?: number | null
  bytes_in?: number | null
  events?: number | null
  anomalies?: number | null
}

/** Outbound vs inbound bytes; inbound is drawn only when reported; anomaly markers only when reported. */
export function InOutTrendChart({ data, height = 280 }: { data: FlowPoint[]; height?: number }) {
  const hasIn = data.some((d) => d.bytes_in != null)
  const reveal = useRevealOnce()
  const marks = data.filter((d) => (d.anomalies ?? 0) > 0 && d.bytes_out != null)
  return (
    <ResponsiveContainer width="100%" height={height}>
      <ComposedChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
        <defs>
          <linearGradient id="outFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#0078D4" stopOpacity={0.3} />
            <stop offset="100%" stopColor="#0078D4" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke={GRID} strokeDasharray="3 3" vertical={false} />
        <XAxis dataKey="timestamp" tickFormatter={formatTime} {...AXIS} minTickGap={32} />
        <YAxis tickFormatter={(v: number) => formatBytes(v)} width={64} {...AXIS} />
        <Tooltip
          {...TOOLTIP}
          labelFormatter={(l) => formatDateTime(String(l))}
          formatter={(v, name) => [formatBytes(Number(v)), name === 'bytes_in' ? 'Inbound' : 'Outbound']}
        />
        <Area type="monotone" dataKey="bytes_out" stroke="#0078D4" strokeWidth={2} fill="url(#outFill)" isAnimationActive={reveal} animationDuration={700} animationEasing="ease-out" />
        {hasIn && <Line type="monotone" dataKey="bytes_in" stroke="#2563EB" strokeWidth={2} dot={false} isAnimationActive={reveal} animationDuration={700} animationEasing="ease-out" />}
        {marks.map((m) => (
          <ReferenceDot key={m.timestamp} x={m.timestamp} y={m.bytes_out as number} r={5} fill="#F43F5E" stroke="#FFFFFF" strokeWidth={2} />
        ))}
      </ComposedChart>
    </ResponsiveContainer>
  )
}

/** Flow/event count per interval. */
export function EventVolumeChart({ data, height = 280 }: { data: FlowPoint[]; height?: number }) {
  const rows = data.filter((d) => d.events != null)
  const reveal = useRevealOnce()
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={rows} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
        <CartesianGrid stroke={GRID} strokeDasharray="3 3" vertical={false} />
        <XAxis dataKey="timestamp" tickFormatter={formatTime} {...AXIS} minTickGap={32} />
        <YAxis width={40} allowDecimals={false} {...AXIS} />
        <Tooltip {...TOOLTIP} cursor={{ fill: '#0078D40D' }} labelFormatter={(l) => formatDateTime(String(l))} formatter={(v) => [v, 'Flows']} />
        <Bar dataKey="events" fill="#2563EB" radius={[4, 4, 0, 0]} isAnimationActive={reveal} animationDuration={700} animationEasing="ease-out" />
      </BarChart>
    </ResponsiveContainer>
  )
}
