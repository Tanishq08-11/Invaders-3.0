import { useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import {
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type SortingState,
} from '@tanstack/react-table'
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  ChevronRight,
  Download,
  FolderOpen,
  Grid2x2,
  Info,
  List,
  Loader2,
  MoreHorizontal,
  Search,
  Upload,
} from 'lucide-react'
import { toast } from 'sonner'
import { useDownload, useFiles, type FileItem } from '@/api/files'
import { ApiError, isApiConfigured } from '@/api/client'
import { PageHeader, Panel } from '@/components/common/Panel'
import { ErrorState, StateBlock } from '@/components/common/States'
import { Button, buttonVariants } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Input } from '@/components/ui/input'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { TableSkeleton } from '@/components/common/Skeletons'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { formatBytes, formatDateTime } from '@/lib/format'
import { routes } from '@/lib/routes'
import { cn } from '@/lib/utils'
import { FileIcon, PermissionBadge } from './shared'

interface RowActions {
  open: (f: FileItem) => void
  details: (f: FileItem) => void
  download: (f: FileItem) => void
  downloadingId: string | null
}

type SortableColumn = {
  getIsSorted: () => false | 'asc' | 'desc'
  toggleSorting: (desc?: boolean) => void
}

function SortHeader({ label, column }: { label: string; column: SortableColumn }) {
  const s = column.getIsSorted()
  return (
    <button type="button" className="inline-flex items-center gap-1 hover:text-foreground" onClick={() => column.toggleSorting(s === 'asc')}>
      {label}
      {s === 'asc' ? <ArrowUp className="size-3" /> : s === 'desc' ? <ArrowDown className="size-3" /> : <ArrowUpDown className="size-3 opacity-40" />}
    </button>
  )
}

function RowMenu({ file, actions }: { file: FileItem; actions: RowActions }) {
  const canDownload = isApiConfigured && file.permissions?.download !== false
  const busy = actions.downloadingId === file.id
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        aria-label={`Actions for ${file.name}`}
        className={cn(buttonVariants({ variant: 'ghost', size: 'icon-sm' }))}
        onClick={(e) => e.stopPropagation()}
      >
        {busy ? <Loader2 className="size-4 animate-spin" /> : <MoreHorizontal className="size-4" />}
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuLabel className="max-w-48 truncate">{file.name}</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {file.kind === 'folder' && (
          <DropdownMenuItem disabled={file.permissions?.view === false} onClick={() => actions.open(file)}>
            <FolderOpen className="size-4" /> Open folder
          </DropdownMenuItem>
        )}
        <DropdownMenuItem onClick={() => actions.details(file)}>
          <Info className="size-4" /> View details
        </DropdownMenuItem>
        {file.kind === 'file' && (
          <DropdownMenuItem disabled={!canDownload || busy} onClick={() => actions.download(file)}>
            <Download className="size-4" /> Download
          </DropdownMenuItem>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

function buildColumns(actions: RowActions): ColumnDef<FileItem>[] {
  return [
    {
      accessorKey: 'name',
      header: ({ column }) => <SortHeader label="Name" column={column} />,
      sortingFn: (a, b) =>
        a.original.kind !== b.original.kind
          ? a.original.kind === 'folder' ? -1 : 1
          : a.original.name.localeCompare(b.original.name),
      cell: ({ row }) => (
        <span className="flex items-center gap-2.5">
          <FileIcon item={row.original} />
          <span className="font-medium">{row.original.name}</span>
        </span>
      ),
    },
    {
      accessorKey: 'size_bytes',
      header: ({ column }) => <SortHeader label="Size" column={column} />,
      sortUndefined: 'last',
      cell: ({ row }) => (
        <span className="text-muted-foreground">{row.original.kind === 'folder' ? '—' : formatBytes(row.original.size_bytes)}</span>
      ),
    },
    {
      accessorKey: 'uploaded_at',
      header: ({ column }) => <SortHeader label="Uploaded" column={column} />,
      sortUndefined: 'last',
      cell: ({ row }) => <span className="whitespace-nowrap text-muted-foreground">{formatDateTime(row.original.uploaded_at)}</span>,
    },
    {
      accessorKey: 'owner',
      header: 'Owner',
      cell: ({ row }) => <span className="text-muted-foreground">{row.original.owner ?? '—'}</span>,
    },
    { id: 'access', header: 'Access', cell: ({ row }) => <PermissionBadge item={row.original} /> },
    {
      id: 'actions',
      header: () => <span className="sr-only">Actions</span>,
      cell: ({ row }) => <RowMenu file={row.original} actions={actions} />,
    },
  ]
}

function DetailsSheet({ file, onClose, actions }: { file: FileItem | null; onClose: () => void; actions: RowActions }) {
  const canDownload = !!file && isApiConfigured && file.permissions?.download !== false
  return (
    <Sheet open={!!file} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-full sm:max-w-md">
        {file && (
          <>
            <SheetHeader>
              <SheetTitle className="flex items-center gap-2 break-all">
                <FileIcon item={file} /> {file.name}
              </SheetTitle>
              <SheetDescription>{file.kind === 'folder' ? 'Folder' : 'File'} details</SheetDescription>
            </SheetHeader>
            <dl className="space-y-4 px-4 text-sm">
              {[
                ['Type', file.kind === 'folder' ? 'Folder' : (file.mime_type ?? 'Unknown')],
                ['Size', file.kind === 'folder' ? '—' : formatBytes(file.size_bytes)],
                ['Uploaded', formatDateTime(file.uploaded_at)],
                ['Owner', file.owner ?? '—'],
              ].map(([k, v]) => (
                <div key={k}>
                  <dt className="text-xs text-muted-foreground">{k}</dt>
                  <dd className="font-medium">{v}</dd>
                </div>
              ))}
              <div>
                <dt className="text-xs text-muted-foreground">Your access</dt>
                <dd>
                  <PermissionBadge item={file} />
                </dd>
              </div>
            </dl>
            <div className="mt-auto flex flex-col gap-2 p-4">
              {file.kind === 'folder' ? (
                <Button
                  disabled={file.permissions?.view === false}
                  onClick={() => {
                    actions.open(file)
                    onClose()
                  }}
                >
                  <FolderOpen className="size-4" /> Open folder
                </Button>
              ) : (
                <Button disabled={!canDownload || actions.downloadingId === file.id} onClick={() => actions.download(file)}>
                  {actions.downloadingId === file.id ? <Loader2 className="size-4 animate-spin" /> : <Download className="size-4" />}
                  Download
                </Button>
              )}
              {!isApiConfigured && (
                <p className="text-xs text-muted-foreground">Downloads are unavailable until the backend is connected.</p>
              )}
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  )
}

// Stable reference: a fresh `[]` on every render makes TanStack Table think the data changed and re-render forever.
const NO_FILES: FileItem[] = []

export function FilesPage() {
  const [params, setParams] = useSearchParams()
  const folder = params.get('folder')
  const view = params.get('view') === 'grid' ? 'grid' : 'list'
  const [filter, setFilter] = useState('')
  const [sorting, setSorting] = useState<SortingState>([{ id: 'name', desc: false }])
  const [detail, setDetail] = useState<FileItem | null>(null)
  const [downloadingId, setDownloadingId] = useState<string | null>(null)
  const { data, isLoading, isError, error, refetch } = useFiles(folder)
  const download = useDownload()

  // Deep link from the dashboard: /employee/files?file=<id> opens that file's details once the listing loads.
  const fileParam = params.get('file')
  useEffect(() => {
    if (!fileParam || !data) return
    const match = data.items.find((f) => f.id === fileParam)
    if (match) setDetail(match)
  }, [fileParam, data])

  const setParam = (k: string, v: string | null) => {
    const next = new URLSearchParams(params)
    if (v) next.set(k, v)
    else next.delete(k)
    setParams(next)
  }

  const actions: RowActions = {
    open: (f) => {
      if (f.kind === 'folder' && f.permissions?.view !== false) setParam('folder', f.id)
    },
    details: setDetail,
    download: (f) => {
      setDownloadingId(f.id)
      download.mutate(f, {
        onSuccess: () => toast.success(`Downloaded ${f.name}`),
        onError: (e) => toast.error('Download failed', { description: e instanceof Error ? e.message : undefined }),
        onSettled: () => setDownloadingId(null),
      })
    },
    downloadingId,
  }

  // Cells need the live action handlers (downloading state, folder navigation).
  const liveColumns = useMemo(() => buildColumns(actions), [downloadingId, folder]) // eslint-disable-line react-hooks/exhaustive-deps

  const table = useReactTable({
    data: data?.items ?? NO_FILES,
    autoResetPageIndex: false,
    columns: liveColumns,
    state: { sorting, globalFilter: filter },
    onSortingChange: setSorting,
    onGlobalFilterChange: setFilter,
    globalFilterFn: (row, _id, value: string) => row.original.name.toLowerCase().includes(String(value).toLowerCase()),
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getRowId: (r) => r.id,
  })
  const rows = table.getRowModel().rows
  const canUploadHere = data?.permissions?.upload !== false && isApiConfigured

  return (
    <div>
      <PageHeader
        title="Files"
        description="Folders and documents you are authorized to access."
        actions={
          <Link
            to={routes.employee.upload + (folder ? `?folder=${encodeURIComponent(folder)}` : '')}
            aria-disabled={!canUploadHere}
            className={cn(buttonVariants(), !canUploadHere && 'pointer-events-none opacity-50')}
          >
            <Upload className="size-4" /> Upload
          </Link>
        }
      />

      <Panel bodyClassName="p-0">
        <div className="flex flex-wrap items-center gap-3 border-b border-border p-3">
          <nav aria-label="Breadcrumb" className="flex min-w-0 flex-1 flex-wrap items-center gap-1 text-sm">
            <button className="text-muted-foreground hover:text-foreground" onClick={() => setParam('folder', null)}>
              All files
            </button>
            {(data?.path ?? []).map((p) => (
              <span key={p.id} className="flex items-center gap-1">
                <ChevronRight className="size-3.5 text-muted-foreground" />
                <button className="hover:text-cyan" onClick={() => setParam('folder', p.id)}>
                  {p.name}
                </button>
              </span>
            ))}
          </nav>
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Search this folder"
              aria-label="Search files"
              className="h-8 w-56 bg-background pl-8"
            />
          </div>
          <div className="flex rounded-md border border-border">
            {(['list', 'grid'] as const).map((v) => (
              <button
                key={v}
                aria-label={`${v} view`}
                aria-pressed={view === v}
                onClick={() => setParam('view', v === 'list' ? null : v)}
                className={cn('p-1.5', view === v ? 'bg-raised text-foreground' : 'text-muted-foreground')}
              >
                {v === 'list' ? <List className="size-4" /> : <Grid2x2 className="size-4" />}
              </button>
            ))}
          </div>
        </div>

        {isLoading ? (
          <TableSkeleton rows={6} cols={5} />
        ) : isError || !isApiConfigured ? (
          error instanceof ApiError && error.status === 403 ? (
            <StateBlock tone="danger" title="Access denied" description="You do not have permission to view this folder." />
          ) : (
            <ErrorState error={error ?? new ApiError('not_configured', '')} onRetry={() => void refetch()} />
          )
        ) : rows.length === 0 ? (
          <StateBlock
            icon={<FolderOpen className="size-5" />}
            title={filter ? 'No files match your search' : 'This folder is empty'}
            description={filter ? undefined : 'There are no files you are authorized to see here.'}
          />
        ) : view === 'list' ? (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                {table.getHeaderGroups().map((hg) => (
                  <TableRow key={hg.id} className="hover:bg-transparent">
                    {hg.headers.map((h) => (
                      <TableHead
                        key={h.id}
                        aria-sort={h.column.getIsSorted() === 'asc' ? 'ascending' : h.column.getIsSorted() === 'desc' ? 'descending' : undefined}
                      >
                        {h.isPlaceholder ? null : flexRender(h.column.columnDef.header, h.getContext())}
                      </TableHead>
                    ))}
                  </TableRow>
                ))}
              </TableHeader>
              <TableBody>
                {rows.map((row) => (
                  <TableRow
                    key={row.id}
                    tabIndex={0}
                    className="cursor-pointer"
                    onClick={() => setDetail(row.original)}
                    onDoubleClick={() => actions.open(row.original)}
                    onKeyDown={(e) => e.key === 'Enter' && setDetail(row.original)}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <TableCell key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</TableCell>
                    ))}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ) : (
          <div className="grid grid-cols-2 gap-3 p-4 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5">
            {rows.map(({ original: f }) => (
              <div key={f.id} className="relative flex flex-col gap-3 rounded-lg border border-border bg-background p-4 transition-colors hover:border-cyan/50">
                <button
                  className="absolute inset-0 rounded-lg"
                  aria-label={`Details for ${f.name}`}
                  onClick={() => setDetail(f)}
                  onDoubleClick={() => actions.open(f)}
                />
                <FileIcon item={f} className="size-8" />
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium" title={f.name}>
                    {f.name}
                  </p>
                  <p className="text-xs text-muted-foreground">{f.kind === 'folder' ? 'Folder' : formatBytes(f.size_bytes)}</p>
                </div>
                <PermissionBadge item={f} />
                <div className="absolute right-2 top-2">
                  <RowMenu file={f} actions={actions} />
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>

      <DetailsSheet
        file={detail}
        onClose={() => {
          setDetail(null)
          if (params.has('file')) setParam('file', null)
        }}
        actions={actions}
      />
    </div>
  )
}
