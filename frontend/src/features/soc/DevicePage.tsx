import { Link, useParams } from 'react-router-dom'
import { useAlerts, useDeviceTimeline } from '@/api/queries'
import { ApiError, isApiConfigured } from '@/api/client'
import { PageHeader, Panel } from '@/components/common/Panel'
import { Crumbs } from '@/components/common/Crumbs'
import { DataSourceBadge, SeverityBadge, StatusBadge } from '@/components/common/Badges'
import { ErrorState, StateBlock, Unavailable } from '@/components/common/States'
import { TrafficAreaChart } from '@/components/charts/Charts'
import { Skeleton } from '@/components/ui/skeleton'
import { formatBytes, formatDateTime, formatNumber } from '@/lib/format'
import { routes } from '@/lib/routes'

export function DevicePage() {
  const { deviceId = '' } = useParams()
  const timeline = useDeviceTimeline(deviceId)
  const alerts = useAlerts()
  const t = timeline.data

  const back = (
    <Crumbs items={[{ label: 'Security Operations', to: routes.soc.overview }, { label: 'Devices' }, { label: deviceId }]} />
  )

  // Related alerts: prefer ids supplied by the device timeline, else alerts that name this device.
  const related = (alerts.data ?? []).filter((a) =>
    t?.related_alert_ids ? t.related_alert_ids.includes(a.id) : a.device_id === deviceId,
  )

  const header = (
    <PageHeader
      back={back}
      title={`Device ${deviceId}`}
      description="Network behavior observed for this device. Attribution to a person requires a verified identity mapping from the backend."
      actions={t && <DataSourceBadge source={t.data_source} />}
    />
  )

  if (timeline.isLoading) {
    return (
      <div>
        {header}
        <div className="grid gap-4 lg:grid-cols-2">
          <Skeleton className="h-72 lg:col-span-2" />
          <Skeleton className="h-48" />
          <Skeleton className="h-48" />
        </div>
      </div>
    )
  }
  if (timeline.isError || !isApiConfigured || !t) {
    return (
      <div>
        {header}
        <Panel>
          <ErrorState error={timeline.error ?? new ApiError('not_configured', '')} onRetry={() => void timeline.refetch()} />
        </Panel>
      </div>
    )
  }

  const events = t.events ?? []
  const baseline = t.baseline
  const series = events.map((e) => ({ timestamp: e.timestamp, bytes_out: e.bytes_out }))
  const unusual = t.unusual_destinations ?? []
  const bursts = t.bursts ?? []

  return (
    <div>
      {header}
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel
          title="Traffic history vs baseline"
          subtitle={baseline?.window ? `Baseline window: ${baseline.window}` : undefined}
          className="lg:col-span-2"
        >
          {series.filter((s) => s.bytes_out != null).length === 0 ? (
            <StateBlock compact title="No traffic history" description="The backend returned no outbound traffic for this device." />
          ) : (
            <>
              <TrafficAreaChart data={series} baseline={baseline?.avg_bytes_out} />
              {baseline?.avg_bytes_out == null && (
                <p className="mt-2 text-xs text-muted-foreground">Baseline unavailable - current activity is shown without a reference.</p>
              )}
            </>
          )}
          {baseline && (
            <dl className="mt-4 grid gap-3 border-t border-border pt-4 text-sm sm:grid-cols-3">
              <div>
                <dt className="text-xs text-muted-foreground">Baseline avg outbound</dt>
                <dd className="font-mono">{formatBytes(baseline.avg_bytes_out)}</dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">Baseline avg connections</dt>
                <dd className="font-mono">{formatNumber(baseline.avg_connections)}</dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">Typical destinations</dt>
                <dd className="font-mono">{baseline.typical_destinations?.length ?? '—'}</dd>
              </div>
            </dl>
          )}
        </Panel>

        <Panel title="Unusual destinations" bodyClassName="p-0">
          {unusual.length === 0 ? (
            <StateBlock compact title="None reported" description="No unusual destinations were supplied for this device." />
          ) : (
            <ul className="divide-y divide-border">
              {unusual.map((d) => (
                <li key={d.destination} className="flex flex-wrap justify-between gap-2 px-4 py-3 text-sm">
                  <span className="font-mono">{d.destination}</span>
                  <span className="text-xs text-muted-foreground">
                    {d.first_seen ? `first seen ${formatDateTime(d.first_seen)} · ` : ''}
                    {formatNumber(d.connection_count)} conn · {formatBytes(d.bytes_out)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Connection bursts" bodyClassName="p-0">
          {bursts.length === 0 ? (
            <StateBlock compact title="None reported" description="No connection bursts were supplied for this device." />
          ) : (
            <ul className="divide-y divide-border">
              {bursts.map((b, i) => (
                <li key={i} className="flex flex-wrap justify-between gap-2 px-4 py-3 text-sm">
                  <span className="text-xs">
                    {formatDateTime(b.start)}
                    {b.end ? ` → ${formatDateTime(b.end)}` : ''}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {formatNumber(b.connection_count)} conn · {formatBytes(b.bytes_out)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Related alerts" className="lg:col-span-2" bodyClassName="p-0">
          {alerts.isLoading ? (
            <div className="p-4"><Skeleton className="h-10 w-full" /></div>
          ) : alerts.isError ? (
            <ErrorState compact error={alerts.error} onRetry={() => void alerts.refetch()} />
          ) : related.length === 0 ? (
            <StateBlock compact title="No related alerts" description="No alerts reference this device." />
          ) : (
            <ul className="divide-y divide-border">
              {related.map((a) => (
                <li key={a.id}>
                  <Link to={routes.soc.alert(a.id)} className="flex flex-wrap items-center gap-3 px-4 py-3 hover:bg-raised">
                    <SeverityBadge severity={a.severity} />
                    <span className="font-mono text-xs">{a.id}</span>
                    <span className="min-w-0 flex-1 truncate font-mono text-sm text-muted-foreground">→ {a.destination ?? 'unknown'}</span>
                    <StatusBadge status={a.status} />
                    <span className="text-xs text-muted-foreground">{formatDateTime(a.created_at)}</span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        {events.length === 0 && (
          <div className="lg:col-span-2">
            <Unavailable>No individual network events were supplied for this device.</Unavailable>
          </div>
        )}
      </div>
    </div>
  )
}
