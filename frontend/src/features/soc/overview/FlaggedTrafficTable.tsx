import { useMemo, useState } from 'react'
import {
  type ColumnDef,
  type SortingState,
  type VisibilityState,
  flexRender,
  getCoreRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
} from '@tanstack/react-table'
import { ArrowDown, ArrowUp, ArrowUpDown, ChevronLeft, ChevronRight, Columns3, FilterX, RefreshCw, Search } from 'lucide-react'
import { ScoringFailedBadge, SeverityBadge, StatusBadge } from '@/components/common/Badges'
import { ErrorState, StateBlock } from '@/components/common/States'
import { TableSkeleton } from '@/components/common/Skeletons'
import { Panel } from '@/components/common/Panel'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuGroup, DropdownMenuLabel, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { formatBytes, formatDateTime, SEVERITY_ORDER } from '@/lib/format'
import { SEVERITY_LABEL } from '@/lib/severity'
import { useNewRowIds } from '@/hooks/useNewRowIds'
import { AlertPreviewSheet } from '../AlertPreviewSheet'
import { cn } from '@/lib/utils'
import { SEVERITIES, type Alert, type Severity } from '@/types'

const NO_ALERTS: Alert[] = []

const columns: ColumnDef<Alert>[] = [
  {
    id: 'source',
    accessorFn: (a) => a.source_ip ?? a.device_id,
    header: 'Source / device',
    cell: ({ row }) => (
      <div className="min-w-0">
        <p className="truncate font-mono text-sm">{row.original.device_id}</p>
        {row.original.source_ip && <p className="truncate font-mono text-[11px] text-muted-foreground">{row.original.source_ip}</p>}
      </div>
    ),
  },
  {
    id: 'destination',
    accessorFn: (a) => a.destination ?? '',
    header: 'Destination',
    cell: ({ row }) => {
      const a = row.original
      return a.destination ? (
        <span className="font-mono text-sm">
          {a.destination}
          {a.destination_port != null && <span className="text-muted-foreground">:{a.destination_port}</span>}
        </span>
      ) : (
        <span className="text-xs text-muted-foreground">Not observed</span>
      )
    },
  },
  {
    id: 'bytes_out',
    accessorFn: (a) => a.bytes_out ?? -1,
    header: 'Outbound data',
    cell: ({ row }) =>
      row.original.bytes_out != null ? (
        <span className="font-mono text-sm">{formatBytes(row.original.bytes_out)}</span>
      ) : (
        <span className="text-xs text-muted-foreground">Not reported</span>
      ),
  },
  {
    id: 'risk',
    accessorFn: (a) => (a.scoring_status === 'failed' ? -1 : (a.risk_score ?? -1)),
    header: 'Risk score',
    cell: ({ row }) => {
      const a = row.original
      if (a.scoring_status === 'failed') return <ScoringFailedBadge />
      if (a.risk_score == null) return <span className="text-xs text-muted-foreground">Unavailable</span>
      return <span className="font-mono text-sm font-medium">{Math.round(a.risk_score)}</span>
    },
  },
  {
    id: 'severity',
    accessorFn: (a) => SEVERITY_ORDER[a.severity],
    header: 'Severity / status',
    cell: ({ row }) => (
      <div className="flex flex-wrap items-center gap-1.5">
        <SeverityBadge severity={row.original.severity} />
        <StatusBadge status={row.original.status} />
      </div>
    ),
  },
  {
    id: 'time',
    accessorFn: (a) => a.created_at,
    header: 'Timestamp',
    cell: ({ row }) => <span className="whitespace-nowrap text-xs text-muted-foreground">{formatDateTime(row.original.created_at)}</span>,
  },
]

/**
 * Flagged network activity: alerts raised from flow metadata. There is no raw-flow endpoint, so this is deliberately
 * not presented as a live feed of all traffic. The alerts query is polled by `useAlerts`.
 */
export function FlaggedTrafficTable({
  alerts,
  loading,
  error,
  onRetry,
  polling,
}: {
  alerts?: Alert[]
  loading: boolean
  error: Error | null
  onRetry: () => void
  polling: boolean
}) {
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState<Severity | null>(null)
  const [selected, setSelected] = useState<Alert | null>(null)
  const sourceIds = useMemo(() => alerts?.map((a) => a.id), [alerts])
  const fresh = useNewRowIds(sourceIds)
  const [visibility, setVisibility] = useState<VisibilityState>({})
  const [sorting, setSorting] = useState<SortingState>([{ id: 'time', desc: true }])

  const data = useMemo(() => {
    const src = alerts ?? NO_ALERTS
    const q = query.trim().toLowerCase()
    return src.filter(
      (a) =>
        (!severity || a.severity === severity) &&
        (!q || [a.device_id, a.source_ip, a.destination, a.id].some((v) => v?.toLowerCase().includes(q))),
    )
  }, [alerts, query, severity])

  const table = useReactTable({
    data,
    columns,
    state: { sorting, columnVisibility: visibility },
    onSortingChange: setSorting,
    onColumnVisibilityChange: setVisibility,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    autoResetPageIndex: false,
    initialState: { pagination: { pageSize: 10 } },
  })
  const rows = table.getRowModel().rows
  const pages = table.getPageCount()
  const page = table.getState().pagination.pageIndex

  return (
    <Panel
      title="Flagged network activity"
      subtitle="Alerts raised from encrypted-traffic metadata. Payloads are never inspected."
      action={
        polling ? (
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border px-2.5 py-1 text-[11px] text-muted-foreground">
            <RefreshCw className="size-3" /> Refreshes every 30 s
          </span>
        ) : undefined
      }
      bodyClassName="p-0"
    >
      <div className="flex flex-wrap items-center gap-2 border-b border-border p-3">
        <div className="relative min-w-52 flex-1 sm:max-w-xs">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={query}
            onChange={(e) => {
              setQuery(e.target.value)
              table.setPageIndex(0)
            }}
            aria-label="Search flagged activity"
            placeholder="Search device, IP, destination, alert ID"
            className="h-8 pl-8 text-xs"
          />
        </div>
        <div className="flex flex-wrap gap-1.5" role="group" aria-label="Filter by severity">
          {SEVERITIES.map((s) => (
            <button
              key={s}
              type="button"
              aria-pressed={severity === s}
              onClick={() => {
                setSeverity(severity === s ? null : s)
                table.setPageIndex(0)
              }}
              className={cn(
                'rounded-md border px-2.5 py-1 text-xs transition-colors',
                severity === s ? 'border-cyan/60 bg-cyan/10 text-cyan' : 'border-border text-muted-foreground hover:bg-accent hover:text-foreground',
              )}
            >
              {SEVERITY_LABEL[s]}
            </button>
          ))}
        </div>
        <div className="ml-auto flex items-center gap-1.5">
          {(query || severity) && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setQuery('')
                setSeverity(null)
                table.setPageIndex(0)
              }}
            >
              <FilterX className="size-3.5" /> Clear filters
            </Button>
          )}
          <DropdownMenu>
            <DropdownMenuTrigger render={<Button variant="outline" size="sm" aria-label="Choose visible columns" />}>
              <Columns3 className="size-3.5" /> Columns
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-48">
              <DropdownMenuGroup>
                <DropdownMenuLabel>Visible columns</DropdownMenuLabel>
                {table.getAllLeafColumns().map((col) => (
                  <DropdownMenuCheckboxItem
                    key={col.id}
                    checked={col.getIsVisible()}
                    onCheckedChange={(v) => col.toggleVisibility(!!v)}
                  >
                    {typeof col.columnDef.header === 'string' ? col.columnDef.header : col.id}
                  </DropdownMenuCheckboxItem>
                ))}
              </DropdownMenuGroup>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      {loading ? (
        <div className="p-4">
          <TableSkeleton rows={5} cols={6} />
        </div>
      ) : error ? (
        <ErrorState compact error={error} onRetry={onRetry} />
      ) : (alerts?.length ?? 0) === 0 ? (
        <StateBlock compact title="No flagged activity" description="No alerts have been raised from the monitored network flows." />
      ) : rows.length === 0 ? (
        <StateBlock compact title="No matches" description="No alerts match the current search or severity filter." />
      ) : (
        <>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                {table.getHeaderGroups().map((hg) => (
                  <TableRow key={hg.id}>
                    {hg.headers.map((h) => {
                      const dir = h.column.getIsSorted()
                      return (
                        <TableHead key={h.id} aria-sort={dir === 'asc' ? 'ascending' : dir === 'desc' ? 'descending' : 'none'}>
                          <button type="button" onClick={h.column.getToggleSortingHandler()} className="inline-flex items-center gap-1 hover:text-foreground">
                            {flexRender(h.column.columnDef.header, h.getContext())}
                            {dir === 'asc' ? <ArrowUp className="size-3" /> : dir === 'desc' ? <ArrowDown className="size-3" /> : <ArrowUpDown className="size-3 opacity-40" />}
                          </button>
                        </TableHead>
                      )
                    })}
                  </TableRow>
                ))}
              </TableHeader>
              <TableBody>
                {rows.map((r) => (
                  <TableRow
                    key={r.id}
                    tabIndex={0}
                    onClick={() => setSelected(r.original)}
                    onKeyDown={(e) => e.key === 'Enter' && setSelected(r.original)}
                    className={cn(
                      'cursor-pointer hover:bg-accent focus-visible:bg-accent focus-visible:outline-none',
                      fresh.has(r.original.id) && 'veylix-row-new',
                    )}
                  >
                    {r.getVisibleCells().map((c) => (
                      <TableCell key={c.id}>{flexRender(c.column.columnDef.cell, c.getContext())}</TableCell>
                    ))}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <div className="flex items-center justify-between gap-2 border-t border-border px-4 py-2.5 text-xs text-muted-foreground">
            <span>
              {data.length} of {alerts?.length} alerts
            </span>
            <div className="flex items-center gap-1">
              <Button variant="ghost" size="icon" aria-label="Previous page" disabled={!table.getCanPreviousPage()} onClick={() => table.previousPage()}>
                <ChevronLeft className="size-4" />
              </Button>
              <span>
                {page + 1} / {Math.max(1, pages)}
              </span>
              <Button variant="ghost" size="icon" aria-label="Next page" disabled={!table.getCanNextPage()} onClick={() => table.nextPage()}>
                <ChevronRight className="size-4" />
              </Button>
            </div>
          </div>
        </>
      )}
      <AlertPreviewSheet alert={selected} onClose={() => setSelected(null)} />
    </Panel>
  )
}
