import { useMemo, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { ArrowDown, ArrowUp, ArrowUpDown, ChevronLeft, ChevronRight, Search, X } from 'lucide-react'
import { useAlerts } from '@/api/queries'
import { isApiConfigured, ApiError } from '@/api/client'
import { PageHeader, Panel } from '@/components/common/Panel'
import { SeverityBadge, StatusBadge } from '@/components/common/Badges'
import { ErrorState, StateBlock } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { TableSkeleton } from '@/components/common/Skeletons'
import { useNewRowIds } from '@/hooks/useNewRowIds'
import { AlertPreviewSheet, RiskCell, Signals } from './AlertPreviewSheet'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { formatDateTime, SEVERITY_ORDER } from '@/lib/format'
import { SEVERITY_LABEL, STATUS_LABEL } from '@/lib/severity'
import { routes } from '@/lib/routes'
import { cn } from '@/lib/utils'
import { SEVERITIES, STATUSES, type Alert, type AlertStatus, type Severity } from '@/types'

type SortKey = 'created_at' | 'risk_score' | 'severity' | 'device_id' | 'status'
const PAGE_SIZE = 15

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

export function AlertCenterPage() {
  const navigate = useNavigate()
  const [params, setParams] = useSearchParams()
  const { data, isLoading, isError, error, refetch } = useAlerts()
  const sourceIds = useMemo(() => data?.map((a) => a.id), [data])
  const fresh = useNewRowIds(sourceIds)
  const [selected, setSelected] = useState<Alert | null>(null)

  const q = params.get('q') ?? ''
  const sev = (params.get('severity')?.split(',').filter(Boolean) ?? []) as Severity[]
  const sts = (params.get('status')?.split(',').filter(Boolean) ?? []) as AlertStatus[]
  const sort = (params.get('sort') as SortKey) || 'created_at'
  const dir = params.get('dir') === 'asc' ? 'asc' : 'desc'
  const page = Math.max(1, Number(params.get('page')) || 1)

  const update = (patch: Record<string, string | null>) => {
    const next = new URLSearchParams(params)
    for (const [k, v] of Object.entries(patch)) {
      if (v) next.set(k, v)
      else next.delete(k)
    }
    if (!('page' in patch)) next.delete('page')
    setParams(next, { replace: true })
  }
  const toggle = <T extends string>(list: T[], v: T) => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v])

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase()
    const filtered = (data ?? []).filter(
      (a) =>
        (sev.length === 0 || sev.includes(a.severity)) &&
        (sts.length === 0 || sts.includes(a.status)) &&
        (!needle ||
          [a.id, a.device_id, a.destination ?? '', ...a.signals.map((s) => s.label)].some((f) => f.toLowerCase().includes(needle))),
    )
    const m = dir === 'asc' ? 1 : -1
    return filtered.sort((a, b) => {
      switch (sort) {
        case 'risk_score':
          // Unscored alerts always sort last regardless of direction.
          if (a.risk_score == null) return b.risk_score == null ? 0 : 1
          if (b.risk_score == null) return -1
          return (a.risk_score - b.risk_score) * m
        case 'severity':
          return (SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]) * m
        case 'device_id':
          return a.device_id.localeCompare(b.device_id) * m
        case 'status':
          return a.status.localeCompare(b.status) * m
        default:
          return a.created_at.localeCompare(b.created_at) * m
      }
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, q, params.get('severity'), params.get('status'), sort, dir])

  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE))
  const current = Math.min(page, pages)
  const visible = rows.slice((current - 1) * PAGE_SIZE, current * PAGE_SIZE)
  const filtering = q || sev.length > 0 || sts.length > 0

  const SortHead = ({ k, children, className }: { k: SortKey; children: React.ReactNode; className?: string }) => (
    <TableHead className={className} aria-sort={sort === k ? (dir === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button type="button" className="inline-flex items-center gap-1 hover:text-foreground" onClick={() => update({ sort: k, dir: sort === k && dir === 'desc' ? 'asc' : 'desc' })}>
        {children}
        {sort === k ? dir === 'asc' ? <ArrowUp className="size-3" /> : <ArrowDown className="size-3" /> : <ArrowUpDown className="size-3 opacity-40" />}
      </button>
    </TableHead>
  )

  return (
    <div>
      <PageHeader
        title="Alert Center"
        description="Incidents raised from anomalous outbound network behavior. Select a row to preview, open it to investigate."
      />

      <Panel bodyClassName="p-0">
        <div className="space-y-3 border-b border-border p-4">
          <div className="relative max-w-md">
            <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={q}
              onChange={(e) => update({ q: e.target.value || null })}
              placeholder="Search by ID, device, destination or signal"
              aria-label="Search alerts"
              className="bg-background pl-9"
            />
          </div>
          <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="mr-1 text-xs text-muted-foreground">Severity</span>
              {SEVERITIES.map((s) => (
                <Chip key={s} active={sev.includes(s)} onClick={() => update({ severity: toggle(sev, s).join(',') || null })}>
                  {SEVERITY_LABEL[s]}
                </Chip>
              ))}
            </div>
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="mr-1 text-xs text-muted-foreground">Status</span>
              {STATUSES.map((s) => (
                <Chip key={s} active={sts.includes(s)} onClick={() => update({ status: toggle(sts, s).join(',') || null })}>
                  {STATUS_LABEL[s]}
                </Chip>
              ))}
            </div>
            {filtering && (
              <Button variant="ghost" size="sm" onClick={() => setParams({}, { replace: true })}>
                <X className="size-3.5" /> Clear filters
              </Button>
            )}
          </div>
        </div>

        {isLoading ? (
          <TableSkeleton rows={6} cols={5} />
        ) : isError || !isApiConfigured ? (
          <ErrorState error={error ?? new ApiError('not_configured', '')} onRetry={() => void refetch()} />
        ) : (data ?? []).length === 0 ? (
          <StateBlock title="No alerts available" description="No alerts available. Connect the backend to begin monitoring." />
        ) : rows.length === 0 ? (
          <StateBlock title="No alerts match these filters" description="Try widening the search or clearing filters." />
        ) : (
          <>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead>ID</TableHead>
                    <SortHead k="created_at">Timestamp</SortHead>
                    <SortHead k="device_id">Device</SortHead>
                    <TableHead>Destination</TableHead>
                    <SortHead k="risk_score">Risk</SortHead>
                    <SortHead k="severity">Severity</SortHead>
                    <TableHead>Signals</TableHead>
                    <SortHead k="status">Status</SortHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {visible.map((a) => (
                    <TableRow
                      key={a.id}
                      tabIndex={0}
                      data-state={selected?.id === a.id ? 'selected' : undefined}
                      className={cn('cursor-pointer', fresh.has(a.id) && 'veylix-row-new')}
                      onClick={() => setSelected(a)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') navigate(routes.soc.alert(a.id))
                        if (e.key === ' ') {
                          e.preventDefault()
                          setSelected(a)
                        }
                      }}
                    >
                      <TableCell className="font-mono text-xs">{a.id}</TableCell>
                      <TableCell className="whitespace-nowrap text-xs text-muted-foreground">{formatDateTime(a.created_at)}</TableCell>
                      <TableCell className="font-mono text-xs">{a.device_id}</TableCell>
                      <TableCell className="font-mono text-xs">{a.destination ?? '—'}</TableCell>
                      <TableCell><RiskCell alert={a} /></TableCell>
                      <TableCell><SeverityBadge severity={a.severity} /></TableCell>
                      <TableCell><Signals alert={a} /></TableCell>
                      <TableCell><StatusBadge status={a.status} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <div className="flex items-center justify-between border-t border-border px-4 py-3 text-xs text-muted-foreground">
              <span>
                {rows.length} alert{rows.length === 1 ? '' : 's'}
                {filtering && data ? ` of ${data.length}` : ''}
              </span>
              <div className="flex items-center gap-2">
                <Button variant="outline" size="icon-sm" disabled={current <= 1} onClick={() => update({ page: String(current - 1) })} aria-label="Previous page">
                  <ChevronLeft className="size-4" />
                </Button>
                <span>
                  Page {current} / {pages}
                </span>
                <Button variant="outline" size="icon-sm" disabled={current >= pages} onClick={() => update({ page: String(current + 1) })} aria-label="Next page">
                  <ChevronRight className="size-4" />
                </Button>
              </div>
            </div>
          </>
        )}
      </Panel>

      <AlertPreviewSheet alert={selected} onClose={() => setSelected(null)} />
    </div>
  )
}
