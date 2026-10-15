import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { ChevronLeft, ChevronRight, ExternalLink, Link2 } from 'lucide-react'
import { useEvent, useEventStats, useEvents } from '@/api/queries'
import { useLiveStatus } from '@/api/live'
import { PageHeader, Panel } from '@/components/common/Panel'
import { DataSourceBadge, DetectionStatusBadge, EventTypeBadge, LiveStatusBadge } from '@/components/common/Badges'
import { ErrorState, StateBlock, Unavailable } from '@/components/common/States'
import { TableSkeleton } from '@/components/common/Skeletons'
import { Button, buttonVariants } from '@/components/ui/button'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { EVENT_TYPE_LABEL, eventSummary } from '@/lib/events'
import { formatBytes, formatDateTime, formatDuration, formatNumber, labelize } from '@/lib/format'
import { routes } from '@/lib/routes'
import { cn } from '@/lib/utils'
import type { EventType } from '@/types'

const TYPES: EventType[] = ['application_activity', 'network_flow', 'network_record', 'network_packet']
const DEFAULT_TYPES: EventType[] = ['application_activity', 'network_flow', 'network_record']
const PAGE = 50

function Chip({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        'rounded-md border px-2.5 py-1 text-xs transition-colors',
        active ? 'border-cyan/60 bg-cyan/10 text-cyan' : 'border-border text-muted-foreground hover:bg-raised hover:text-foreground',
      )}
    >
      {children}
    </button>
  )
}

function DetailRow({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div>
      <dt className="text-xs text-muted-foreground">{k}</dt>
      <dd className="break-words font-mono text-sm">{v ?? '—'}</dd>
    </div>
  )
}

function EventDetailSheet({ uuid, onClose }: { uuid: string | null; onClose: () => void }) {
  const q = useEvent(uuid)
  const e = q.data
  const d = (e?.details ?? {}) as Record<string, unknown>
  const tls = (d.tls ?? null) as Record<string, unknown> | null
  return (
    <Sheet open={!!uuid} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-full overflow-y-auto border-border bg-surface sm:max-w-lg">
        <SheetHeader>
          <SheetTitle className="font-mono">{uuid}</SheetTitle>
          <SheetDescription>Event detail and correlated evidence</SheetDescription>
        </SheetHeader>
        <div className="space-y-5 px-4 pb-6 text-sm">
          {q.isLoading ? (
            <Skeleton className="h-48 w-full" />
          ) : q.isError || !e ? (
            <ErrorState compact error={q.error} onRetry={() => void q.refetch()} />
          ) : (
            <>
              <div className="flex flex-wrap gap-2">
                <EventTypeBadge type={e.event_type} />
                <DataSourceBadge source={e.data_source} />
                <DetectionStatusBadge status={e.detection_status} />
              </div>
              {e.note && <p className="rounded-lg bg-raised px-3 py-2 text-xs text-muted-foreground">{e.note}</p>}
              <dl className="grid grid-cols-2 gap-3">
                <DetailRow k="Time" v={formatDateTime(e.timestamp)} />
                <DetailRow k="Source" v={e.source} />
                {e.event_type === 'application_activity' ? (
                  <>
                    <DetailRow k="User" v={e.user ? `${e.user.username} (${e.user.department ?? '—'})` : e.user_id} />
                    <DetailRow k="Action" v={`${e.action ?? '—'} · ${e.outcome ?? '—'}`} />
                    <DetailRow k="Client address (seen by portal)" v={e.src_ip} />
                    <DetailRow k="Size" v={formatBytes(d.size_bytes as number)} />
                    <DetailRow k="Location" v={d.location as string} />
                    <DetailRow k="File id" v={d.file_id as number} />
                  </>
                ) : (
                  <>
                    <DetailRow k="Source" v={`${e.src_ip ?? '—'}${e.src_port != null ? `:${e.src_port}` : ''}`} />
                    <DetailRow k="Destination" v={`${e.dst_ip ?? '—'}${e.dst_port != null ? `:${e.dst_port}` : ''}`} />
                    <DetailRow k="Protocol" v={e.protocol} />
                    <DetailRow k="Direction" v={e.direction} />
                    <DetailRow k="Bytes out / in" v={`${formatBytes(e.bytes_out)} / ${e.bytes_in != null ? formatBytes(e.bytes_in) : '—'}`} />
                    <DetailRow k="Packets out / in" v={`${formatNumber(e.packets_out)} / ${e.packets_in != null ? formatNumber(e.packets_in) : '—'}`} />
                    <DetailRow k="Duration" v={formatDuration(e.duration_seconds)} />
                    <DetailRow k="Anomaly score" v={e.anomaly_score != null ? e.anomaly_score : 'Not scored'} />
                    {d.end_reason != null && <DetailRow k="Flow ended by" v={labelize(String(d.end_reason))} />}
                    {e.packet_event_count != null && <DetailRow k="Packet events in flow" v={e.packet_event_count} />}
                  </>
                )}
              </dl>
              {e.ai_error && <p className="text-xs text-sev-medium">Detector: {e.ai_error}</p>}
              {e.processing_error && <p className="text-xs text-sev-critical">Processing: {e.processing_error}</p>}

              {tls && (
                <section>
                  <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">TLS handshake metadata (not decrypted)</h3>
                  <dl className="grid grid-cols-2 gap-3">
                    {Object.entries(tls)
                      .filter(([k]) => k !== 'ja3_string')
                      .map(([k, v]) => (
                        <DetailRow key={k} k={labelize(k)} v={Array.isArray(v) ? v.join(', ') : String(v)} />
                      ))}
                  </dl>
                </section>
              )}

              <section>
                <h3 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  <Link2 className="size-3.5" /> Correlated evidence
                </h3>
                {e.correlations.length === 0 ? (
                  <Unavailable>
                    No correlation recorded
                    {(d.correlation as { status?: string } | undefined)?.status
                      ? ` (${labelize(String((d.correlation as { status?: string }).status))})`
                      : ''}
                    . Events are linked only when the evidence is specific; uncertain cases stay unlinked.
                  </Unavailable>
                ) : (
                  <ul className="space-y-2">
                    {e.correlations.map((c) => (
                      <li key={c.correlation_id} className="rounded-lg border border-border p-3">
                        <div className="mb-1 flex flex-wrap items-center gap-2 text-xs">
                          <span className="font-medium">{labelize(c.method)}</span>
                          <span className={cn('rounded px-1.5 py-0.5', c.confidence === 'high' ? 'bg-green-600/10 text-green-700' : 'bg-amber-500/10 text-amber-700')}>
                            {c.confidence} confidence
                          </span>
                          {c.time_delta_s != null && <span className="text-muted-foreground">Δt {c.time_delta_s}s</span>}
                        </div>
                        {c.related_event && <p className="font-mono text-xs">{eventSummary(c.related_event)}</p>}
                        {c.rationale && <p className="mt-1 text-xs text-muted-foreground">{c.rationale}</p>}
                      </li>
                    ))}
                  </ul>
                )}
              </section>

              {e.alert_id && (
                <Link to={routes.soc.alert(e.alert_id)} className={cn(buttonVariants({ variant: 'outline' }), 'w-full')}>
                  Open alert <ExternalLink className="size-4" />
                </Link>
              )}
            </>
          )}
        </div>
      </SheetContent>
    </Sheet>
  )
}

export function EventLogPage() {
  const [types, setTypes] = useState<EventType[]>(DEFAULT_TYPES)
  const [cursors, setCursors] = useState<(number | null)[]>([null])
  const [selected, setSelected] = useState<string | null>(null)
  const live = useLiveStatus()
  const beforeId = cursors[cursors.length - 1]
  const filters = useMemo(() => ({ types, beforeId, limit: PAGE }), [types, beforeId])
  const events = useEvents(filters)
  const stats = useEventStats()

  const toggle = (t: EventType) => {
    setTypes((cur) => (cur.includes(t) ? cur.filter((x) => x !== t) : [...cur, t]))
    setCursors([null])
  }

  return (
    <div>
      <PageHeader
        title="Event Log"
        description="Every stored event: application activity recorded by the portal, and network evidence from capture, PCAP, replay or ingestion. Detection status shows whether the AI evaluated each event."
        actions={<LiveStatusBadge status={live} />}
      />

      <Panel bodyClassName="p-0">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 border-b border-border p-4">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="mr-1 text-xs text-muted-foreground">Type</span>
            {TYPES.map((t) => (
              <Chip key={t} active={types.includes(t)} onClick={() => toggle(t)}>
                {EVENT_TYPE_LABEL[t]}
                {stats.data?.by_type[t] != null && <span className="ml-1 text-muted-foreground">{formatNumber(stats.data.by_type[t])}</span>}
              </Chip>
            ))}
          </div>
          {stats.data && (
            <span className="text-xs text-muted-foreground">
              {formatNumber(stats.data.correlations)} correlation{stats.data.correlations === 1 ? '' : 's'} ·{' '}
              {formatNumber(stats.data.by_detection_status.unavailable ?? 0)} stored without AI score
            </span>
          )}
        </div>

        {events.isLoading ? (
          <TableSkeleton rows={8} cols={6} />
        ) : events.isError ? (
          <ErrorState error={events.error} onRetry={() => void events.refetch()} />
        ) : types.length === 0 ? (
          <StateBlock title="No event types selected" description="Select at least one event type." />
        ) : (events.data?.items.length ?? 0) === 0 ? (
          <StateBlock title="No events yet" description="Events appear here once files are used in the portal, the collector runs, or a PCAP is analysed." />
        ) : (
          <>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead>Time</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Summary</TableHead>
                    <TableHead>Bytes</TableHead>
                    <TableHead>Detection</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {events.data?.items.map((e) => (
                    <TableRow
                      key={e.event_uuid}
                      tabIndex={0}
                      className="cursor-pointer"
                      data-state={selected === e.event_uuid ? 'selected' : undefined}
                      onClick={() => setSelected(e.event_uuid)}
                      onKeyDown={(k) => k.key === 'Enter' && setSelected(e.event_uuid)}
                    >
                      <TableCell className="whitespace-nowrap text-xs text-muted-foreground">{formatDateTime(e.timestamp)}</TableCell>
                      <TableCell><EventTypeBadge type={e.event_type} /></TableCell>
                      <TableCell><DataSourceBadge source={e.data_source} /></TableCell>
                      <TableCell className="font-mono text-xs">
                        {eventSummary(e)}
                        {e.tls_sni && <span className="ml-2 text-muted-foreground">SNI {e.tls_sni}</span>}
                      </TableCell>
                      <TableCell className="text-xs">{formatBytes(e.bytes_out)}</TableCell>
                      <TableCell><DetectionStatusBadge status={e.detection_status} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <div className="flex items-center justify-between border-t border-border px-4 py-3 text-xs text-muted-foreground">
              <span>{cursors.length === 1 ? 'Newest events' : `Page ${cursors.length}`}</span>
              <div className="flex items-center gap-2">
                <Button variant="outline" size="icon-sm" disabled={cursors.length === 1} onClick={() => setCursors((c) => c.slice(0, -1))} aria-label="Newer events">
                  <ChevronLeft className="size-4" />
                </Button>
                <Button
                  variant="outline"
                  size="icon-sm"
                  disabled={!events.data?.next_before_id}
                  onClick={() => setCursors((c) => [...c, events.data?.next_before_id ?? null])}
                  aria-label="Older events"
                >
                  <ChevronRight className="size-4" />
                </Button>
              </div>
            </div>
          </>
        )}
      </Panel>

      <EventDetailSheet uuid={selected} onClose={() => setSelected(null)} />
    </div>
  )
}
