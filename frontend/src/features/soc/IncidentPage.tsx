import { useEffect, useMemo, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { motion, useReducedMotion } from 'motion/react'
import {
  Activity,
  ArrowLeft,
  ArrowRight,
  Check,
  ChevronDown,
  Gavel,
  GitCompare,
  Link2,
  MonitorSmartphone,
  Network,
  Save,
  ScanSearch,
} from 'lucide-react'
import { toast } from 'sonner'
import { useAlert, useAlerts, useConnection, useDeviceTimeline, useUpdateAlert } from '@/api/queries'
import { ApiError, isApiConfigured } from '@/api/client'
import { PageHeader, Panel } from '@/components/common/Panel'
import { DataSourceBadge, ScoringFailedBadge, SeverityBadge, StatusBadge } from '@/components/common/Badges'
import { ErrorState, StateBlock, Unavailable } from '@/components/common/States'
import { ScoreGauge } from '@/components/common/ScoreGauge'
import { Crumbs } from '@/components/common/Crumbs'
import { Term, TERMS } from '@/components/common/Term'
import { ContributionChart } from '@/components/charts/Charts'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Textarea } from '@/components/ui/textarea'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { formatBytes, formatDateTime, formatDuration, labelize } from '@/lib/format'
import { STATUS_LABEL } from '@/lib/severity'
import { routes } from '@/lib/routes'
import { cn } from '@/lib/utils'
import { STATUSES, type AlertStatus } from '@/types'

/** How a piece of information should be read by the analyst. */
type Provenance = 'fact' | 'model' | 'analyst'
const PROVENANCE: Record<Provenance, { label: string; hint: string; cls: string }> = {
  fact: { label: 'Observed fact', hint: 'Reported by the network telemetry as-is.', cls: 'border-cyan/30 bg-cyan/10 text-cyan' },
  model: { label: 'Model indicator', hint: 'Produced by the detection model. A reason to look closer, not proof.', cls: 'border-amber-300/60 bg-amber-50 text-amber-700' },
  analyst: { label: 'Analyst conclusion', hint: 'Recorded by a person through the backend.', cls: 'border-green-300/60 bg-green-50 text-green-700' },
}

function Tag({ kind }: { kind: Provenance }) {
  const p = PROVENANCE[kind]
  return (
    <span title={p.hint} className={cn('inline-flex shrink-0 items-center rounded-full border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide', p.cls)}>
      {p.label}
    </span>
  )
}

function Card({ title, kind, subtitle, children, className }: { title: string; kind: Provenance; subtitle?: string; children: React.ReactNode; className?: string }) {
  return (
    <Panel title={title} subtitle={subtitle} action={<Tag kind={kind} />} className={className}>
      {children}
    </Panel>
  )
}

function Field({ label, children, mono }: { label: React.ReactNode; children: React.ReactNode; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className={cn('mt-0.5 break-words text-sm', mono && 'font-mono')}>{children}</dd>
    </div>
  )
}

function Fold({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <details className="group rounded-lg border border-border bg-raised/40">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-2 px-3 py-2 text-sm font-medium outline-none focus-visible:ring-2 focus-visible:ring-cyan/50">
        {title}
        <ChevronDown className="size-4 text-muted-foreground transition-transform duration-200 group-open:rotate-180" />
      </summary>
      <div className="border-t border-border px-3 py-3">{children}</div>
    </details>
  )
}

const STEPS = [
  { key: 'overview', label: 'Alert Overview', short: 'Overview', icon: ScanSearch },
  { key: 'evidence', label: 'Network Evidence', short: 'Evidence', icon: Network },
  { key: 'behavior', label: 'Behavioral Analysis', short: 'Behavior', icon: GitCompare },
  { key: 'related', label: 'Related Activity', short: 'Related', icon: Link2 },
  { key: 'decision', label: 'Analyst Decision', short: 'Decision', icon: Gavel },
] as const

type StepState = 'complete' | 'unavailable' | 'pending'

export function IncidentPage() {
  const { alertId = '' } = useParams()
  const [params, setParams] = useSearchParams()
  const reduce = useReducedMotion()
  const { data: a, isLoading, isError, error, refetch } = useAlert(alertId)
  const timeline = useDeviceTimeline(a?.device_id ?? '')
  const allAlerts = useAlerts()
  const { state: conn } = useConnection()
  const mutation = useUpdateAlert(alertId)
  const [status, setStatus] = useState<AlertStatus | ''>('')
  const [note, setNote] = useState('')

  const stepIndex = Math.min(STEPS.length - 1, Math.max(0, (Number(params.get('step')) || 1) - 1))
  const goTo = (i: number) => {
    const next = new URLSearchParams(params)
    next.set('step', String(i + 1))
    setParams(next, { replace: true })
  }

  // Seed the form from the backend record whenever a fresh record arrives.
  useEffect(() => {
    if (a) {
      setStatus(a.status)
      setNote(a.analyst_note ?? '')
    }
  }, [a])

  const back = (
    <Crumbs items={[{ label: 'Security Operations', to: routes.soc.overview }, { label: 'Alert Center', to: routes.soc.alerts }, { label: alertId }]} />
  )

  const events = useMemo(() => [...(a?.events ?? [])].sort((x, y) => x.timestamp.localeCompare(y.timestamp)), [a?.events])
  const contributions = a?.risk_contributions ?? []
  const meta = Object.entries(a?.metadata ?? {})
  const t = timeline.data
  const relatedAlerts = (allAlerts.data ?? []).filter((x) =>
    x.id === alertId ? false : t?.related_alert_ids ? t.related_alert_ids.includes(x.id) : x.device_id === a?.device_id,
  )

  if (isLoading) {
    return (
      <div>
        {back}
        <Skeleton className="mb-4 h-10 w-80" />
        <Skeleton className="mb-4 h-16 w-full" />
        <div className="grid gap-4 lg:grid-cols-3">
          <Skeleton className="h-64" />
          <Skeleton className="h-64 lg:col-span-2" />
        </div>
      </div>
    )
  }
  if (isError || !isApiConfigured || !a) {
    return (
      <div>
        {back}
        <Panel>
          <ErrorState error={error ?? new ApiError('not_configured', '')} onRetry={() => void refetch()} />
        </Panel>
      </div>
    )
  }

  const canAct = conn === 'connected'
  const dirty = status !== a.status || note !== (a.analyst_note ?? '')

  // A step is "complete" only when the backend supplied the evidence it needs (or, for the decision, a person
  // moved the alert out of "new"). Merely visiting a step never completes it.
  const stepState: StepState[] = [
    a.risk_score != null || a.scoring_status === 'failed' ? 'complete' : 'unavailable',
    events.length > 0 || a.bytes_out != null ? 'complete' : 'unavailable',
    contributions.length > 0 || t?.baseline ? 'complete' : 'unavailable',
    relatedAlerts.length > 0 || (t?.unusual_destinations?.length ?? 0) > 0 || (t?.bursts?.length ?? 0) > 0 ? 'complete' : 'unavailable',
    a.status !== 'new' ? 'complete' : 'pending',
  ]
  const stateWord: Record<StepState, string> = {
    complete: 'Evidence available',
    unavailable: 'Evidence not provided by backend',
    pending: 'Awaiting analyst',
  }

  const save = () => {
    if (!status) return
    mutation.mutate(
      { status, note: note || undefined },
      {
        onSuccess: () => toast.success('Investigation updated'),
        onError: (e) => toast.error('Update failed', { description: e instanceof Error ? e.message : undefined }),
      },
    )
  }

  const totalOut = events.reduce((sum, e) => sum + (e.bytes_out ?? 0), 0)
  const hasOut = events.some((e) => e.bytes_out != null)
  const destinations = new Set(events.map((e) => e.dst_ip).filter(Boolean))
  const maxAnomaly = events.reduce<number | null>(
    (m, e) => (e.anomaly_score == null ? m : m == null ? e.anomaly_score : Math.max(m, e.anomaly_score)),
    null,
  )

  const reviewRows: [string, StepState][] = [
    ['Alert overview', stepState[0]],
    ['Network evidence', stepState[1]],
    ['Behavioral analysis', stepState[2]],
    ['Related activity', stepState[3]],
  ]

  const panels = [
    // 1 --------------------------------------------------------------- Alert overview
    <div key="overview" className="grid gap-4 lg:grid-cols-3">
      <Card title="Risk assessment" kind="model">
        <div className="flex flex-col items-center gap-3">
          {a.scoring_status === 'failed' ? (
            <div className="space-y-2 text-center">
              <ScoringFailedBadge />
              <p className="text-xs text-muted-foreground">Scoring failed for this incident. This is not a safe or zero-risk result.</p>
            </div>
          ) : (
            <ScoreGauge score={a.risk_score} severity={a.severity} />
          )}
          <p className="text-center text-[11px] text-muted-foreground">
            The <Term hint={TERMS.risk}>risk score</Term> reflects VEYLIX prioritization rules. It is not the probability that data was
            stolen.
          </p>
        </div>
      </Card>

      <Card title="Alert summary" kind="fact" className="lg:col-span-2">
        <dl className="grid gap-4 sm:grid-cols-2">
          <Field label="Raised">{formatDateTime(a.created_at)}</Field>
          <Field label="Device" mono>
            <Link to={routes.soc.device(a.device_id)} className="inline-flex items-center gap-1 text-cyan hover:underline">
              <MonitorSmartphone className="size-3.5" />
              {a.device_id}
            </Link>
          </Field>
          <Field label="Destination" mono>
            {a.destination ?? '—'}
            {a.destination_port != null ? `:${a.destination_port}` : ''}
          </Field>
          <Field label="Model version">{a.model_version ?? 'Not reported'}</Field>
          <div className="sm:col-span-2">
            <dt className="mb-1 flex items-center gap-2 text-xs text-muted-foreground">
              <Term hint={TERMS.signals}>Detection signals</Term> <Tag kind="model" />
            </dt>
            <dd className="flex flex-wrap gap-1.5">
              {a.signals.length === 0 ? (
                <span className="text-sm text-muted-foreground">None reported</span>
              ) : (
                a.signals.map((s) => (
                  <span key={s.code} className="rounded-md border border-border bg-raised px-2 py-0.5 text-xs">
                    {s.label}
                  </span>
                ))
              )}
            </dd>
          </div>
        </dl>
      </Card>

      <Card title="Why this alert was raised" kind="model" className="lg:col-span-3">
        {a.explanation ? (
          <p className="text-sm leading-relaxed">{a.explanation}</p>
        ) : (
          <Unavailable>The backend did not provide a detection explanation for this incident.</Unavailable>
        )}
      </Card>
    </div>,

    // 2 --------------------------------------------------------------- Network evidence
    <div key="evidence" className="grid gap-4 lg:grid-cols-3">
      <Card title="Observed traffic" kind="fact" subtitle="From the alert and its correlated events" className="lg:col-span-3">
        <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Field label="Destination" mono>
            {a.destination ?? 'Not observed'}
            {a.destination_port != null ? `:${a.destination_port}` : ''}
          </Field>
          <Field label="Source IP" mono>
            {a.source_ip ?? 'Not reported'}
          </Field>
          <Field label="Outbound (alert)">{a.bytes_out != null ? formatBytes(a.bytes_out) : 'Not reported'}</Field>
          <Field label="Correlated events">{events.length === 0 ? 'None provided' : events.length}</Field>
        </dl>
        {events.length > 0 && (
          <p className="mt-4 rounded-lg border border-dashed border-border px-3 py-2 text-xs text-muted-foreground">
            Computed from the events below: {hasOut ? `${formatBytes(totalOut)} outbound` : 'outbound size not reported'} across{' '}
            {destinations.size || 'an unreported number of'} destination{destinations.size === 1 ? '' : 's'}.
          </p>
        )}
      </Card>

      <Panel
        title="Correlated network events"
        subtitle="Connection metadata only - payloads are never inspected"
        action={<Tag kind="fact" />}
        className="lg:col-span-3"
        bodyClassName="p-0"
      >
        {events.length === 0 ? (
          <StateBlock compact title="No correlated events" description="The backend did not return network events for this incident." />
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Destination</TableHead>
                  <TableHead>Protocol</TableHead>
                  <TableHead>Out</TableHead>
                  <TableHead>In</TableHead>
                  <TableHead>Duration</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.map((e, i) => (
                  <TableRow key={e.id ?? i}>
                    <TableCell className="whitespace-nowrap font-mono text-xs">{formatDateTime(e.timestamp)}</TableCell>
                    <TableCell className="font-mono text-xs">{e.src_ip ?? e.device_id ?? '—'}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {e.dst_ip ?? '—'}
                      {e.dst_port != null ? `:${e.dst_port}` : ''}
                      {e.tls_sni && <span className="block text-muted-foreground">SNI {e.tls_sni}</span>}
                    </TableCell>
                    <TableCell className="text-xs">{e.protocol ?? '—'}</TableCell>
                    <TableCell className="font-mono text-xs">{formatBytes(e.bytes_out)}</TableCell>
                    <TableCell className="font-mono text-xs">{formatBytes(e.bytes_in)}</TableCell>
                    <TableCell className="font-mono text-xs">{formatDuration(e.duration_seconds)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </Panel>

      <div className="lg:col-span-3">
        <Fold title={`Supporting metadata (${meta.length})`}>
          {meta.length === 0 ? (
            <p className="text-xs text-muted-foreground">No additional metadata provided.</p>
          ) : (
            <dl className="grid gap-x-8 gap-y-2 text-xs sm:grid-cols-2">
              {meta.map(([k, v]) => (
                <div key={k} className="flex justify-between gap-3">
                  <dt className="text-muted-foreground">{labelize(k)}</dt>
                  <dd className="break-all text-right font-mono">{v == null ? '—' : String(v)}</dd>
                </div>
              ))}
            </dl>
          )}
        </Fold>
      </div>
    </div>,

    // 3 --------------------------------------------------------------- Behavioral analysis
    <div key="behavior" className="grid gap-4 lg:grid-cols-3">
      <Card
        title="Risk-signal contributions"
        kind="model"
        subtitle="How each signal contributed, as reported by the risk engine"
        className="lg:col-span-2"
      >
        {contributions.length === 0 ? (
          <Unavailable>Risk contributions were not provided for this incident.</Unavailable>
        ) : (
          <>
            <ContributionChart data={contributions} />
            <ul className="mt-3 divide-y divide-border text-xs">
              {contributions.map((c) => (
                <li key={c.signal} className="py-2">
                  <div className="flex flex-wrap justify-between gap-3">
                    <span className="font-medium">{c.label ?? labelize(c.signal)}</span>
                    <span className="font-mono text-muted-foreground">
                      {c.observed_value != null && <>observed {String(c.observed_value)}</>}
                      {c.baseline_value != null && <> · baseline {String(c.baseline_value)}</>}
                    </span>
                  </div>
                  {c.explanation && <p className="mt-0.5 text-muted-foreground">{c.explanation}</p>}
                </li>
              ))}
            </ul>
          </>
        )}
      </Card>

      <Card title="Device baseline" kind="fact" subtitle="Typical behavior used for comparison">
        {timeline.isLoading ? (
          <Skeleton className="h-28 w-full" />
        ) : !isApiConfigured || timeline.isError || !t?.baseline ? (
          <Unavailable>
            The backend did not provide a <Term hint={TERMS.baseline}>baseline</Term> for this device.
          </Unavailable>
        ) : (
          <dl className="space-y-3">
            <Field label="Window">{t.baseline.window ?? 'Not reported'}</Field>
            <Field label="Average outbound">{t.baseline.avg_bytes_out != null ? formatBytes(t.baseline.avg_bytes_out) : 'Not reported'}</Field>
            <Field label="Average connections">{t.baseline.avg_connections ?? 'Not reported'}</Field>
            <Field label="Typical destinations">
              {t.baseline.typical_destinations?.length ? t.baseline.typical_destinations.join(', ') : 'Not reported'}
            </Field>
          </dl>
        )}
      </Card>

      <Card title="Anomaly indicators" kind="model" className="lg:col-span-3" subtitle="Raw model output - not a probability">
        {maxAnomaly == null && a.signals.length === 0 ? (
          <Unavailable>No anomaly indicators were provided for this incident.</Unavailable>
        ) : (
          <dl className="grid gap-4 sm:grid-cols-3">
            <Field label={<Term hint={TERMS.anomaly}>Highest event anomaly score</Term>}>
              {maxAnomaly == null ? 'Not reported' : maxAnomaly.toFixed(2)}
            </Field>
            <Field label="Signals reported">{a.signals.length}</Field>
            <Field label={<Term hint={TERMS.risk}>Risk score</Term>}>
              {a.scoring_status === 'failed' ? 'Scoring failed' : a.risk_score != null ? Math.round(a.risk_score) : 'Unavailable'}
            </Field>
          </dl>
        )}
      </Card>
    </div>,

    // 4 --------------------------------------------------------------- Related activity
    <div key="related" className="grid gap-4 lg:grid-cols-3">
      <Panel
        title="Related alerts"
        subtitle={t?.related_alert_ids ? 'Supplied by the device timeline' : 'Other alerts naming the same device'}
        action={<Tag kind="fact" />}
        className="lg:col-span-2"
        bodyClassName="p-0"
      >
        {allAlerts.isLoading ? (
          <div className="space-y-2 p-4">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        ) : allAlerts.isError || !isApiConfigured ? (
          <ErrorState compact error={allAlerts.error ?? new ApiError('not_configured', '')} onRetry={() => void allAlerts.refetch()} />
        ) : relatedAlerts.length === 0 ? (
          <StateBlock compact title="No related alerts" description="No other alerts were returned for this device." />
        ) : (
          <ul className="divide-y divide-border">
            {relatedAlerts.map((r) => (
              <li key={r.id}>
                <Link to={routes.soc.alert(r.id)} className="flex flex-wrap items-center gap-3 px-4 py-3 text-sm transition-colors hover:bg-accent">
                  <SeverityBadge severity={r.severity} />
                  <span className="font-mono text-xs text-muted-foreground">{r.id}</span>
                  <span className="min-w-0 flex-1 truncate font-mono">{r.destination ?? 'unknown destination'}</span>
                  <StatusBadge status={r.status} />
                  <span className="text-xs text-muted-foreground">{formatDateTime(r.created_at)}</span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Card title="Device patterns" kind="fact" subtitle="From the device timeline">
        {timeline.isLoading ? (
          <Skeleton className="h-24 w-full" />
        ) : !isApiConfigured || timeline.isError || !t ? (
          <Unavailable>Device timeline data is unavailable.</Unavailable>
        ) : (
          <div className="space-y-3 text-sm">
            <div>
              <p className="text-xs text-muted-foreground">Unusual destinations</p>
              {t.unusual_destinations?.length ? (
                <ul className="mt-1 space-y-1">
                  {t.unusual_destinations.slice(0, 5).map((d) => (
                    <li key={d.destination} className="flex justify-between gap-2 font-mono text-xs">
                      <span className="truncate">{d.destination}</span>
                      <span className="text-muted-foreground">{d.connection_count ?? '—'}×</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-xs text-muted-foreground">None reported</p>
              )}
            </div>
            <div>
              <p className="text-xs text-muted-foreground">
                <Term hint={TERMS.burst}>Connection bursts</Term>
              </p>
              <p className="text-xs">{t.bursts?.length ? `${t.bursts.length} reported` : 'None reported'}</p>
            </div>
            <Link to={routes.soc.device(a.device_id)} className="inline-flex items-center gap-1 text-xs text-cyan hover:underline">
              Open full device investigation <ArrowRight className="size-3" />
            </Link>
          </div>
        )}
      </Card>
    </div>,

    // 5 --------------------------------------------------------------- Analyst decision
    <div key="decision" className="grid gap-4 lg:grid-cols-3">
      <Card title="Findings to review" kind="fact" subtitle="What the backend provided for this alert" className="lg:col-span-2">
        <ul className="space-y-2 text-sm">
          {reviewRows.map(([label, st], i) => (
            <li key={label} className="flex items-center justify-between gap-3 rounded-lg border border-border px-3 py-2">
              <button type="button" onClick={() => goTo(i)} className="text-left hover:text-cyan">
                {label}
              </button>
              <span className={cn('text-xs', st === 'complete' ? 'text-green-700' : 'text-muted-foreground')}>{stateWord[st]}</span>
            </li>
          ))}
        </ul>
        <p className="mt-4 rounded-lg border border-dashed border-border px-3 py-2 text-xs leading-relaxed text-muted-foreground">
          An anomaly score or risk score alone does not confirm data exfiltration. Record what you verified, and choose the status that
          reflects your own assessment.
        </p>
      </Card>

      <Card title="Analyst decision" kind="analyst" subtitle="Saved to the backend">
        <div className="space-y-3">
          <div>
            <label htmlFor="status" className="mb-1 block text-xs text-muted-foreground">
              Investigation status
            </label>
            <select
              id="status"
              value={status}
              disabled={!canAct || mutation.isPending}
              onChange={(e) => setStatus(e.target.value as AlertStatus)}
              className="h-9 w-full rounded-md border border-input bg-background px-2 text-sm disabled:opacity-50"
            >
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {STATUS_LABEL[s]}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="note" className="mb-1 block text-xs text-muted-foreground">
              Analyst note
            </label>
            <Textarea
              id="note"
              value={note}
              maxLength={2000}
              disabled={!canAct || mutation.isPending}
              onChange={(e) => setNote(e.target.value)}
              rows={5}
              className="bg-background"
            />
          </div>
          <Button className="w-full" disabled={!canAct || !dirty || mutation.isPending} onClick={save}>
            <Save className="size-4" /> {mutation.isPending ? 'Saving…' : 'Save decision'}
          </Button>
          {!canAct && <p className="text-xs text-sev-medium">Backend not connected - analyst actions are disabled.</p>}
          {a.updated_at && <p className="text-[11px] text-muted-foreground">Last updated {formatDateTime(a.updated_at)}</p>}
        </div>
      </Card>
    </div>,
  ]

  return (
    <div>
      <PageHeader
        back={back}
        title={`Incident ${a.id}`}
        description="Potential exfiltration indicator based on anomalous outbound network behavior. This is not confirmation of data theft."
        actions={
          <>
            <SeverityBadge severity={a.severity} />
            <StatusBadge status={a.status} />
            <DataSourceBadge source={a.data_source} />
          </>
        }
      />

      {/* Stepper */}
      <nav aria-label="Investigation steps" className="mb-5">
        <ol className="grid grid-cols-5 gap-1 rounded-2xl border border-border bg-card p-2 shadow-[0_14px_34px_-24px_rgba(0,120,212,0.25)]">
          {STEPS.map((s, i) => {
            const active = i === stepIndex
            const st = stepState[i]
            const Icon = s.icon
            return (
              <li key={s.key} className="relative min-w-0">
                <button
                  type="button"
                  onClick={() => goTo(i)}
                  aria-current={active ? 'step' : undefined}
                  title={`${s.label} - ${stateWord[st]}`}
                  className={cn(
                    'flex w-full flex-col items-center gap-1.5 rounded-xl px-1 py-2.5 text-center outline-none transition-colors duration-200 focus-visible:ring-2 focus-visible:ring-cyan/60 sm:flex-row sm:justify-center sm:gap-2.5 sm:px-3',
                    active ? 'bg-cyan/10 text-foreground' : 'text-muted-foreground hover:bg-accent hover:text-foreground',
                  )}
                >
                  <span
                    className={cn(
                      'flex size-7 shrink-0 items-center justify-center rounded-full border text-xs font-semibold transition-colors duration-200',
                      active && 'border-cyan bg-cyan text-white',
                      !active && st === 'complete' && 'border-green-600/40 bg-green-50 text-green-700',
                      !active && st !== 'complete' && 'border-border bg-raised',
                      !active && st === 'unavailable' && 'border-dashed',
                    )}
                  >
                    {active ? <Icon className="size-3.5" /> : st === 'complete' ? <Check className="size-3.5" /> : i + 1}
                  </span>
                  <span className="min-w-0">
                    <span className="hidden truncate text-[13px] font-medium sm:block">{s.label}</span>
                    <span className="block truncate text-[11px] font-medium sm:hidden">{s.short}</span>
                  </span>
                </button>
              </li>
            )
          })}
        </ol>
        <p className="mt-2 text-xs text-muted-foreground" aria-live="polite">
          Step {stepIndex + 1} of {STEPS.length}: {STEPS[stepIndex].label} - {stateWord[stepState[stepIndex]]}.
        </p>
      </nav>

      <motion.div
        key={stepIndex}
        initial={reduce ? false : { opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.2, ease: 'easeOut' }}
      >
        {panels[stepIndex]}
      </motion.div>

      <div className="mt-5 flex items-center justify-between gap-3">
        <Button variant="outline" disabled={stepIndex === 0} onClick={() => goTo(stepIndex - 1)}>
          <ArrowLeft className="size-4" /> Previous
        </Button>
        <span className="hidden items-center gap-1.5 text-xs text-muted-foreground sm:inline-flex">
          <Activity className="size-3.5" /> Viewing a step does not mark it complete
        </span>
        <Button disabled={stepIndex === STEPS.length - 1} onClick={() => goTo(stepIndex + 1)}>
          Next <ArrowRight className="size-4" />
        </Button>
      </div>
    </div>
  )
}
