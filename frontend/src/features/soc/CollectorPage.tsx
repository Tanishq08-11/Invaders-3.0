import { useState } from 'react'
import { toast } from 'sonner'
import { AlertTriangle, FlaskConical, Loader2, Lock, Play, Radar, Square, Upload } from 'lucide-react'
import {
  useAnalysePcap,
  useCaptureInterfaces,
  useCollectorStatus,
  useHealth,
  useStartCollector,
  useStopCollector,
} from '@/api/queries'
import { useLiveStatus } from '@/api/live'
import { ApiError } from '@/api/client'
import { useAuth } from '@/auth/AuthProvider'
import { canOperateCollector } from '@/auth/auth.types'
import { Stagger } from '@/components/common/Bento'
import { PageHeader, Panel } from '@/components/common/Panel'
import { CollectorModeBadge, LiveStatusBadge } from '@/components/common/Badges'
import { ErrorState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { formatBytes, formatDuration, formatNumber } from '@/lib/format'
import type { CollectorStatus, PcapResult } from '@/types'

const errorText = (e: unknown) => (e instanceof ApiError ? e.message : 'The request failed.')

function Stat({ label, value, hint, tone }: { label: string; value: React.ReactNode; hint?: string; tone?: 'danger' | 'warning' }) {
  return (
    <div className="rounded-lg border border-border bg-background/40 px-3 py-2.5" title={hint}>
      <dt className="text-[11px] uppercase tracking-wider text-muted-foreground">{label}</dt>
      <dd
        className={
          'mt-1 font-mono text-lg font-semibold tabular-nums ' +
          (tone === 'danger' ? 'text-sev-critical' : tone === 'warning' ? 'text-sev-medium' : '')
        }
      >
        {value}
      </dd>
    </div>
  )
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3 py-1.5 text-sm">
      <dt className="text-muted-foreground">{k}</dt>
      <dd className="text-right font-medium">{v}</dd>
    </div>
  )
}

function ModeBanner({ status }: { status: CollectorStatus }) {
  if (status.mode === 'simulation')
    return (
      <div role="status" className="mb-4 flex items-start gap-3 rounded-xl border border-fuchsia-500/40 bg-fuchsia-500/10 px-4 py-3 text-sm text-fuchsia-800">
        <FlaskConical className="mt-0.5 size-4 shrink-0" />
        <div>
          <p className="font-semibold">Simulation mode — synthetic packets, not real network traffic.</p>
          <p className="text-xs">Every event produced now is stored with source “simulation” and is labelled as such everywhere.</p>
        </div>
      </div>
    )
  if (status.mode === 'failed')
    return (
      <div role="alert" className="mb-4 flex items-start gap-3 rounded-xl border border-sev-critical/40 bg-sev-critical/10 px-4 py-3 text-sm text-sev-critical">
        <AlertTriangle className="mt-0.5 size-4 shrink-0" />
        <div>
          <p className="font-semibold">Capture is not running.</p>
          <p className="text-xs">{status.last_collector_error ?? 'The collector reported a failure without details.'}</p>
        </div>
      </div>
    )
  return null
}

function CaptureControls({ status, operator }: { status: CollectorStatus; operator: boolean }) {
  const ifaces = useCaptureInterfaces(operator)
  const start = useStartCollector()
  const stop = useStopCollector()
  const [chosen, setIface] = useState<string | null>(null)
  const [filter, setFilter] = useState('ip')
  const busy = start.isPending || stop.isPending || status.mode === 'starting'
  const running = status.is_running || status.mode === 'starting'
  // Defaults to the first authorised interface; never starts capture by itself.
  const iface = chosen ?? ifaces.data?.interfaces.find((i) => i.allowed)?.name ?? ''

  if (!operator)
    return (
      <div className="flex items-start gap-2 rounded-lg border border-dashed border-border px-3 py-3 text-xs text-muted-foreground">
        <Lock className="mt-0.5 size-3.5 shrink-0" />
        Starting or stopping capture and analysing PCAP files requires an administrator (collector operator) account. You can monitor the
        collector here.
      </div>
    )

  const run = (mode: 'live' | 'simulation') =>
    start.mutate(
      { mode, interface: mode === 'live' ? iface : undefined, filter },
      {
        onSuccess: (r) => {
          if (r.status === 'already_running') toast.info(`Collector is already running (${r.mode}).`)
          else toast.success(mode === 'live' ? `Live capture started on ${iface}` : 'Simulation started (synthetic traffic)')
          if (r.warning) toast.warning(r.warning)
        },
      },
    )

  const liveBlocked = !status.live_capture_available
  return (
    <div className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-[1fr_12rem]">
        <label className="text-xs text-muted-foreground">
          Capture interface
          <select
            className="mt-1 h-8 w-full rounded-lg border border-input bg-background px-2 text-sm text-foreground disabled:opacity-50"
            value={iface}
            disabled={running || busy || ifaces.isLoading}
            onChange={(e) => setIface(e.target.value)}
            aria-label="Capture interface"
          >
            <option value="">{ifaces.isLoading ? 'Loading interfaces…' : 'Select an interface'}</option>
            {ifaces.data?.interfaces.map((i) => (
              <option key={i.name} value={i.name} disabled={!i.allowed}>
                {i.name}
                {i.description && i.description !== i.name ? ` — ${i.description}` : ''}
                {i.ips?.length ? ` (${i.ips.join(', ')})` : ''}
                {!i.allowed ? ' [not authorised]' : ''}
              </option>
            ))}
          </select>
        </label>
        <label className="text-xs text-muted-foreground">
          BPF filter
          <Input className="mt-1 font-mono" value={filter} disabled={running || busy} onChange={(e) => setFilter(e.target.value)} aria-label="Capture filter" />
        </label>
      </div>
      {ifaces.isError && <p className="text-xs text-sev-critical">Interfaces could not be listed: {errorText(ifaces.error)}</p>}
      {liveBlocked && (
        <p className="text-xs text-sev-medium">
          Live capture is unavailable on this host: {status.live_capture_unavailable_reason ?? 'reason not reported'}
        </p>
      )}
      <p className="text-[11px] text-muted-foreground">Only capture on interfaces and networks you are authorised to monitor. Payloads are never decrypted or stored.</p>
      <div className="flex flex-wrap gap-2">
        <Button onClick={() => run('live')} disabled={running || busy || !iface || liveBlocked}>
          {start.isPending && start.variables?.mode === 'live' ? <Loader2 className="size-4 animate-spin" /> : <Play className="size-4" />}
          Start live capture
        </Button>
        <Button variant="outline" onClick={() => run('simulation')} disabled={running || busy}>
          <FlaskConical className="size-4" />
          Start simulation
        </Button>
        <Button
          variant="destructive"
          onClick={() => stop.mutate(undefined, { onSuccess: (r) => toast.success(r.status === 'not_running' ? 'Collector was not running.' : 'Collector stopped; open flows flushed.') })}
          disabled={(!running && status.mode !== 'failed') || busy}
        >
          {stop.isPending ? <Loader2 className="size-4 animate-spin" /> : <Square className="size-4" />}
          {status.mode === 'failed' ? 'Clear failure' : 'Stop'}
        </Button>
      </div>
      {start.isError && <p role="alert" className="text-xs text-sev-critical">Start failed: {errorText(start.error)}</p>}
      {stop.isError && <p role="alert" className="text-xs text-sev-critical">Stop failed: {errorText(stop.error)}</p>}
    </div>
  )
}

function PcapPanel({ operator, last }: { operator: boolean; last?: Record<string, unknown> | null }) {
  const analyse = useAnalysePcap()
  const [file, setFile] = useState<File | null>(null)
  const result: PcapResult | Record<string, unknown> | null | undefined = analyse.data ?? last
  return (
    <Panel title="Offline PCAP analysis" subtitle="Same metadata → flow → event path as live capture; events are labelled “pcap”">
      {operator ? (
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault()
            if (file) analyse.mutate({ file })
          }}
        >
          <label className="text-xs text-muted-foreground">
            Capture file (.pcap, .pcapng)
            <input
              type="file"
              accept=".pcap,.pcapng,.cap"
              className="mt-1 block text-xs file:mr-2 file:rounded-md file:border file:border-border file:bg-raised file:px-2 file:py-1"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
          </label>
          <Button type="submit" variant="outline" disabled={!file || analyse.isPending}>
            {analyse.isPending ? <Loader2 className="size-4 animate-spin" /> : <Upload className="size-4" />}
            Analyse
          </Button>
        </form>
      ) : (
        <p className="text-xs text-muted-foreground">PCAP analysis requires an administrator account.</p>
      )}
      {analyse.isError && <p role="alert" className="mt-3 text-xs text-sev-critical">Analysis failed: {errorText(analyse.error)}</p>}
      {result && (
        <dl className="mt-3 grid grid-cols-2 gap-x-6 text-sm sm:grid-cols-3">
          <Row k="File" v={String(result.file ?? '—')} />
          <Row k="Status" v={String(result.status ?? '—')} />
          <Row k="Packets read" v={formatNumber(result.total_packets as number)} />
          <Row k="Malformed" v={formatNumber(result.malformed_packets as number)} />
          <Row k="Events stored" v={formatNumber(result.events_ingested as number)} />
          <Row k="Flows" v={formatNumber(result.flow_events as number)} />
          <Row k="TLS handshakes" v={formatNumber(result.tls_handshakes as number)} />
          <Row k="Alerts" v={formatNumber(result.threats_detected as number)} />
          <Row k="Errors" v={formatNumber(result.processing_errors as number)} />
          {typeof result.error === 'string' && <Row k="Error" v={result.error} />}
        </dl>
      )}
    </Panel>
  )
}

export function CollectorPage() {
  const { user } = useAuth()
  const operator = canOperateCollector(user?.role)
  const status = useCollectorStatus()
  const health = useHealth()
  const live = useLiveStatus()
  const s = status.data
  const detector = health.data?.detector

  return (
    <Stagger>
      <PageHeader
        title="Network Collector"
        description="Header-metadata capture from authorised interfaces, bidirectional flow aggregation and TLS handshake metadata. No payload is decrypted or stored."
        actions={
          <>
            {s && <CollectorModeBadge mode={s.mode} />}
            <LiveStatusBadge status={live} />
          </>
        }
      />

      {status.isLoading ? (
        <Skeleton className="h-64 w-full" />
      ) : status.isError || !s ? (
        <Panel>
          <ErrorState error={status.error} onRetry={() => void status.refetch()} />
        </Panel>
      ) : (
        <>
          <ModeBanner status={s} />
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
            <Panel title="Capture control" subtitle={s.is_running ? `Running on ${s.active_interface ?? '—'}` : 'Collector idle'} className="xl:col-span-2">
              <CaptureControls status={s} operator={operator} />
            </Panel>
            <Panel title="Capabilities" subtitle="Reported by the backend; nothing here is assumed">
              <dl className="divide-y divide-border">
                <Row k="Live capture on host" v={s.live_capture_available ? (s.live_capture_verified ? 'Available (verified)' : 'Available (not yet started)') : 'Unavailable'} />
                <Row k="AI detector" v={detector ? `${detector.state}${detector.final_model === false ? ' · not final model' : ''}` : 'Not reported'} />
                <Row k="TLS handshake parser" v={s.tls?.builtin_handshake_parser ?? 'Not reported'} />
                <Row k="JA3" v={s.tls?.ja3 ? 'Built-in' : 'Not reported'} />
                <Row k="JA4" v={s.tls?.ja4 ?? 'Not reported'} />
                <Row k="Zeek enrichment" v={s.tls?.zeek ? (s.tls.zeek.available ? 'Available' : 'Not installed') : 'Not reported'} />
                <Row k="Packet events" v={s.packet_events_enabled ? 'Stored' : 'Flows only'} />
              </dl>
              {detector && !detector.available && (
                <p className="mt-2 text-[11px] text-sev-medium">
                  Events are stored and shown, but none are scored: {detector.reason ?? 'no detector loaded'}.
                </p>
              )}
            </Panel>
          </div>

          <Panel title="Counters (current run)" subtitle="Outcomes, not attempts: a failed write is never counted as stored" className="mt-4">
            <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4 xl:grid-cols-6">
              <Stat label="Packets observed" value={formatNumber(s.packets_captured)} />
              <Stat label="Traffic" value={formatBytes(s.bytes_captured)} />
              <Stat label="Events stored" value={formatNumber(s.events_ingested)} hint="Packet + flow events persisted" />
              <Stat label="Flows completed" value={formatNumber(s.flows_completed)} />
              <Stat label="Active flows" value={formatNumber(s.active_flows)} />
              <Stat label="Throughput" value={s.is_running ? `${s.throughput_pps ?? 0} pkt/s` : '—'} />
              <Stat label="Processing errors" value={formatNumber(s.processing_errors)} tone={s.processing_errors ? 'danger' : undefined} />
              <Stat label="Dropped (queue full)" value={formatNumber(s.packets_dropped)} tone={s.packets_dropped ? 'warning' : undefined} />
              <Stat label="Malformed packets" value={formatNumber(s.corrupted_packets)} />
              <Stat label="Collector errors" value={formatNumber(s.collector_errors)} tone={s.collector_errors ? 'danger' : undefined} />
              <Stat label="Uptime" value={s.is_running ? formatDuration(s.uptime_seconds) : '—'} />
              <Stat label="Source" value={s.source ?? '—'} />
            </dl>
            {(s.last_processing_error || s.last_collector_error) && (
              <div className="mt-3 space-y-1 text-xs">
                {s.last_collector_error && <p className="text-sev-critical">Last capture error: {s.last_collector_error}</p>}
                {s.last_processing_error && <p className="text-sev-critical">Last processing error: {s.last_processing_error}</p>}
              </div>
            )}
          </Panel>

          <div className="mt-4">
            <PcapPanel operator={operator} last={s.last_pcap} />
          </div>
          {!operator && (
            <p className="mt-4 flex items-center gap-1.5 text-xs text-muted-foreground">
              <Radar className="size-3.5" /> Read-only view for security analysts.
            </p>
          )}
        </>
      )}
    </Stagger>
  )
}
