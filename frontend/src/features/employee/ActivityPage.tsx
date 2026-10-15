import { useMemo, useState } from 'react'
import { ArrowDownToLine, ArrowUpFromLine, Ban, Eye } from 'lucide-react'
import { useActivity, type ActivityEntry } from '@/api/files'
import { ApiError, isApiConfigured } from '@/api/client'
import { PageHeader, Panel } from '@/components/common/Panel'
import { ErrorState, StateBlock } from '@/components/common/States'
import { ListSkeleton } from '@/components/common/Skeletons'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { formatDateTime } from '@/lib/format'

const ICON = { upload: ArrowUpFromLine, download: ArrowDownToLine, access: Eye, denied: Ban }
const RESULT_COLOR = { success: 'text-emerald-600', denied: 'text-sev-high', failed: 'text-sev-critical' }

const TABS = [
  { value: 'all', label: 'All', match: () => true },
  { value: 'upload', label: 'Uploads', match: (e: ActivityEntry) => e.action === 'upload' },
  { value: 'download', label: 'Downloads', match: (e: ActivityEntry) => e.action === 'download' },
  { value: 'issues', label: 'Denied / failed', match: (e: ActivityEntry) => e.result !== 'success' },
] as const

export function ActivityPage() {
  const { data, isLoading, isError, error, refetch } = useActivity()
  const [tab, setTab] = useState<string>('all')

  const rows = useMemo(() => {
    const match = TABS.find((t) => t.value === tab)?.match ?? (() => true)
    return [...(data ?? [])].filter(match).sort((a, b) => b.timestamp.localeCompare(a.timestamp))
  }, [data, tab])

  return (
    <div>
      <PageHeader
        title="My activity"
        description="Your file uploads, downloads and access attempts. This is application activity, not security-detection evidence."
      />
      <Tabs value={tab} onValueChange={(v) => setTab(String(v))}>
        <TabsList>
          {TABS.map((t) => (
            <TabsTrigger key={t.value} value={t.value}>
              {t.label}
              {data && <span className="ml-1.5 text-xs text-muted-foreground">{data.filter(t.match).length}</span>}
            </TabsTrigger>
          ))}
        </TabsList>
      </Tabs>

      <Panel className="mt-4" bodyClassName="p-0">
        {isLoading ? (
          <ListSkeleton rows={5} />
        ) : isError || !isApiConfigured ? (
          <ErrorState error={error ?? new ApiError('not_configured', '')} onRetry={() => void refetch()} />
        ) : rows.length === 0 ? (
          <StateBlock
            title={data && data.length > 0 ? 'Nothing in this view' : 'No activity yet'}
            description={data && data.length > 0 ? 'Try another tab.' : 'Your file activity will appear here.'}
          />
        ) : (
          <ul className="divide-y divide-border">
            {rows.map((e) => {
              const Icon = ICON[e.action]
              return (
                <li key={e.id} className="flex items-center gap-3 px-4 py-3">
                  <Icon className="size-4 shrink-0 text-muted-foreground" />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm">
                      <span className="font-medium capitalize">{e.action}</span>
                      {e.file_name && <span className="text-muted-foreground"> · {e.file_name}</span>}
                    </p>
                    {e.detail && <p className="text-xs text-muted-foreground">{e.detail}</p>}
                  </div>
                  <span className={`text-xs capitalize ${RESULT_COLOR[e.result]}`}>{e.result}</span>
                  <span className="hidden text-xs text-muted-foreground sm:inline">{formatDateTime(e.timestamp)}</span>
                </li>
              )
            })}
          </ul>
        )}
      </Panel>
    </div>
  )
}
