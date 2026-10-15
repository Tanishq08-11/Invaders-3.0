import { Link } from 'react-router-dom'
import { Activity, Cpu, MonitorSmartphone, ShieldAlert, Siren } from 'lucide-react'
import { useAlerts, useHealth, useMetrics } from '@/api/queries'
import { ApiError, isApiConfigured } from '@/api/client'
import { BentoCard, Stagger } from '@/components/common/Bento'
import { PageHeader, Panel } from '@/components/common/Panel'
import { DataSourceBadge } from '@/components/common/Badges'
import { ErrorState, StateBlock, Unavailable } from '@/components/common/States'
import { EventVolumeChart, InOutTrendChart, SeverityBarChart } from '@/components/charts/Charts'
import { NumberTicker } from '@/components/ui/number-ticker'
import { Skeleton } from '@/components/ui/skeleton'
import { formatDateTime } from '@/lib/format'
import { routes } from '@/lib/routes'
import { SEVERITIES, type Alert, type Severity } from '@/types'
import { FlaggedTrafficTable } from './overview/FlaggedTrafficTable'
import { ThreatAnalysis } from './overview/ThreatAnalysis'

const NO_ALERTS: Alert[] = []

function Metric({
  label,
  value,
  icon,
  loading,
  to,
  note,
  accent,
}: {
  label: string
  value?: number | null
  icon: React.ReactNode
  loading: boolean
  to?: string
  note: string
  accent?: string
}) {
  const body = (
    <BentoCard as="div" className="h-full p-4">
      <div className="flex items-center justify-between text-muted-foreground">
        <span className="text-xs font-medium uppercase tracking-wider">{label}</span>
        <span style={accent ? { color: accent } : undefined}>{icon}</span>
      </div>
      <div className="mt-3 min-h-10">
        {loading ? (
          <Skeleton className="h-9 w-24" />
        ) : value == null ? (
          <span className="text-3xl font-semibold tracking-tight text-muted-foreground/60">—</span>
        ) : (
          <NumberTicker value={value} className="text-3xl font-semibold tracking-tight tabular-nums" />
        )}
      </div>
      <p className="mt-1 min-h-4 text-[11px] text-muted-foreground">{value == null && !loading ? note : ''}</p>
    </BentoCard>
  )
  return to ? (
    <Link to={to} className="block rounded-2xl focus-visible:outline-2 focus-visible:outline-cyan">
      {body}
    </Link>
  ) : (
    body
  )
}

export function SocOverviewPage() {
  const metrics = useMetrics()
  const health = useHealth()
  const alerts = useAlerts()
  const m = metrics.data
  const received = alerts.data ?? NO_ALERTS
  const unavailableNote = !isApiConfigured
    ? 'Awaiting backend connection'
    : metrics.isError
      ? 'Metrics unavailable'
      : 'Not reported by backend'

  // Prefer backend-computed figures; otherwise count what was actually received.
  const alertTotal = alerts.data ? alerts.data.length : null
  const highRisk =
    m?.high_priority_alerts ??
    (alerts.data ? alerts.data.filter((a) => a.severity === 'critical' || a.severity === 'high').length : null)

  const dist: { severity: Severity; count: number }[] | null = m?.severity_distribution
    ? SEVERITIES.map((s) => ({ severity: s, count: m.severity_distribution?.[s] ?? 0 })).filter((d) => d.count > 0)
    : alerts.data
      ? SEVERITIES.map((s) => ({ severity: s, count: alerts.data.filter((a) => a.severity === s).length })).filter((d) => d.count > 0)
      : null

  const trend = m?.traffic_trend ?? []
  const hasOut = trend.some((p) => p.bytes_out != null)
  const hasEvents = trend.some((p) => p.events != null)
  const hasIn = trend.some((p) => p.bytes_in != null)
  const source = m?.data_source ?? health.data?.data_source
  const notConfigured = new ApiError('not_configured', 'Backend URL not configured')

  return (
    <Stagger>
      <PageHeader
        title="Security Overview"
        description="Anomalous outbound activity across monitored devices, inferred from encrypted-traffic metadata."
        actions={<DataSourceBadge source={source} />}
      />

      {/* SECTION 1 - overview metrics */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Network flows" value={m?.observed_events} icon={<Activity className="size-4" />} loading={metrics.isLoading} note={unavailableNote} />
        <Metric
          label="Alerts"
          value={alertTotal}
          icon={<ShieldAlert className="size-4" />}
          loading={alerts.isLoading}
          to={routes.soc.alerts}
          note={isApiConfigured ? 'Alerts unavailable' : 'Awaiting backend connection'}
        />
        <Metric
          label="High risk"
          value={highRisk}
          icon={<Siren className="size-4" />}
          loading={metrics.isLoading && alerts.isLoading}
          to={routes.soc.alerts}
          note={unavailableNote}
          accent="#F97316"
        />
        <Metric label="Monitored devices" value={m?.monitored_devices} icon={<MonitorSmartphone className="size-4" />} loading={metrics.isLoading} note={unavailableNote} />
      </div>

      {/* SECTION 2 - flagged traffic (not labelled "live": there is no raw-flow stream) */}
      <div className="mt-4">
        <FlaggedTrafficTable
          alerts={alerts.data}
          loading={alerts.isLoading}
          error={alerts.isError || !isApiConfigured ? ((alerts.error ?? notConfigured) as Error) : null}
          onRetry={() => void alerts.refetch()}
          polling={isApiConfigured}
        />
      </div>

      {/* SECTION 3 - threat analysis + severity + system status (asymmetric) */}
      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <ThreatAnalysis alerts={received} />

        <div className="flex flex-col gap-4">
          <Panel title="Alerts by severity" subtitle="Distribution of received alerts">
            {alerts.isLoading || metrics.isLoading ? (
              <Skeleton className="h-40 w-full" />
            ) : dist === null ? (
              <Unavailable>{isApiConfigured ? 'Severity data is unavailable.' : 'Awaiting backend connection.'}</Unavailable>
            ) : dist.length === 0 ? (
              <StateBlock compact title="No alerts" description="No alerts have been raised." />
            ) : (
              <SeverityBarChart data={dist} />
            )}
          </Panel>

          <Panel title="Detection & system status" subtitle="Reported by the backend health check">
            {health.isLoading ? (
              <Skeleton className="h-32 w-full" />
            ) : health.isError || !isApiConfigured ? (
              <ErrorState compact error={health.error ?? notConfigured} onRetry={() => void health.refetch()} />
            ) : (
              <dl className="space-y-3 text-sm">
                {[
                  ['Service', health.data?.status],
                  ['Detection model', health.data?.model_loaded == null ? null : health.data.model_loaded ? 'Loaded' : 'Not loaded'],
                  ['Model version', health.data?.model_version],
                  ['Database', health.data?.database],
                  ['Ingestion', health.data?.ingestion],
                  ['Last event', health.data?.last_event_at ? formatDateTime(health.data.last_event_at) : null],
                ].map(([k, v]) => (
                  <div key={k as string} className="flex items-center justify-between gap-3">
                    <dt className="flex items-center gap-2 text-muted-foreground">
                      {k === 'Detection model' && <Cpu className="size-3.5" />}
                      {k}
                    </dt>
                    <dd className={v ? 'font-medium' : 'text-muted-foreground'}>{v ?? 'Not reported'}</dd>
                  </div>
                ))}
              </dl>
            )}
          </Panel>
        </div>
      </div>

      {/* SECTION 4 - traffic trends */}
      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel
          title={hasIn ? 'Inbound vs outbound traffic' : 'Outbound traffic'}
          subtitle={hasIn ? 'Bytes over time; red markers show reported anomalies' : 'Inbound volume is not reported by the backend'}
          className="xl:col-span-2"
        >
          {metrics.isLoading ? (
            <Skeleton className="h-[280px] w-full" />
          ) : metrics.isError || !isApiConfigured ? (
            <ErrorState compact error={metrics.error ?? notConfigured} onRetry={() => void metrics.refetch()} />
          ) : !hasOut ? (
            <StateBlock compact title="No traffic data available" description="The backend did not return a traffic trend." />
          ) : (
            <InOutTrendChart data={trend} />
          )}
        </Panel>

        <Panel title="Flow volume" subtitle="Observed flows per interval">
          {metrics.isLoading ? (
            <Skeleton className="h-[280px] w-full" />
          ) : metrics.isError || !isApiConfigured ? (
            <Unavailable>{isApiConfigured ? 'Flow volume is unavailable.' : 'Awaiting backend connection.'}</Unavailable>
          ) : !hasEvents ? (
            <StateBlock compact title="No flow counts reported" description="The trend did not include per-interval flow counts." />
          ) : (
            <EventVolumeChart data={trend} />
          )}
        </Panel>
      </div>
    </Stagger>
  )
}
