import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ArrowUpRight, FolderOpen, HardDrive, PlugZap, RefreshCw, Upload } from 'lucide-react'
import { useActivity, useFiles, useProfile } from '@/api/files'
import { isApiConfigured } from '@/api/client'
import AnimatedList from '@/components/AnimatedList'
import FadeContent from '@/components/FadeContent'
import { BentoCard, BentoHead, GhostRows, Sparkline, Stagger } from '@/components/common/Bento'
import { ListSkeleton } from '@/components/common/Skeletons'
import { buttonVariants } from '@/components/ui/button'
import { NumberTicker } from '@/components/ui/number-ticker'
import { Skeleton } from '@/components/ui/skeleton'
import { formatBytes, formatDateTime, formatRelative } from '@/lib/format'
import { routes } from '@/lib/routes'
import { cn } from '@/lib/utils'
import { FileIcon } from './shared'

/** Re-renders every `ms` so relative timestamps stay accurate. */
function useNow(ms = 30_000) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), ms)
    return () => clearInterval(id)
  }, [ms])
  return now
}

const RESULT_DOT = { success: 'bg-emerald-400', denied: 'bg-sev-high', failed: 'bg-sev-critical' } as const

/** Daily counts for the last 7 days from real activity timestamps (oldest -> newest). */
function dailySeries(timestamps: string[], now: number): number[] | null {
  const DAY = 86_400_000
  const startOfToday = new Date(now).setHours(0, 0, 0, 0)
  const buckets = Array<number>(7).fill(0)
  for (const t of timestamps) {
    const ms = new Date(t).getTime()
    if (Number.isNaN(ms)) continue
    const age = Math.floor((startOfToday - new Date(ms).setHours(0, 0, 0, 0)) / DAY)
    if (age >= 0 && age < 7) buckets[6 - age]++
  }
  // A trend line only makes sense with activity on at least two different days.
  return buckets.filter((n) => n > 0).length >= 2 ? buckets : null
}

function Stat({
  label,
  value,
  loading,
  spark,
}: {
  label: string
  value?: number
  loading: boolean
  spark?: number[] | null
}) {
  return (
    <div className="min-w-0 px-5 py-4 first:pl-0">
      <p className="text-[11px] uppercase tracking-wider text-muted-foreground">{label}</p>
      <div className="mt-1 flex items-end justify-between gap-2">
        <div className="text-3xl font-semibold leading-none tracking-tight">
          {loading ? (
            <Skeleton className="h-7 w-12" />
          ) : value == null ? (
            <span className="text-muted-foreground/60" aria-label={`${label} unavailable`}>
              –
            </span>
          ) : (
            <NumberTicker value={value} />
          )}
        </div>
        {spark && <Sparkline values={spark} className="text-cyan/70" />}
      </div>
    </div>
  )
}

function StorageRing({ used, quota }: { used: number; quota: number }) {
  const pct = Math.min(100, (used / quota) * 100)
  const r = 54
  const c = 2 * Math.PI * r
  return (
    <div className="relative mx-auto size-40" role="img" aria-label={`${Math.round(pct)} percent of storage used`}>
      <svg viewBox="0 0 140 140" className="size-full -rotate-90">
        <circle cx="70" cy="70" r={r} fill="none" stroke="#DCE8F5" strokeWidth="10" />
        <circle
          cx="70"
          cy="70"
          r={r}
          fill="none"
          stroke="#0078D4"
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={`${(c * pct) / 100} ${c}`}
          style={{ transition: 'stroke-dasharray 700ms ease-out' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-semibold tracking-tight">{Math.round(pct)}%</span>
        <span className="text-[11px] text-muted-foreground">used</span>
      </div>
    </div>
  )
}

export function EmployeeDashboardPage() {
  const profile = useProfile()
  const files = useFiles(null)
  const activity = useActivity()
  const navigate = useNavigate()
  const now = useNow()

  const p = profile.data
  const offline = !isApiConfigured || (profile.isError && files.isError && activity.isError)
  const retry = () => {
    void profile.refetch()
    void files.refetch()
    void activity.refetch()
  }

  const allItems = files.data?.items
  const recent = [...(allItems ?? [])]
    .filter((f) => f.kind === 'file')
    .sort((a, b) => (b.uploaded_at ?? '').localeCompare(a.uploaded_at ?? ''))
    .slice(0, 8)
  const folders = (allItems ?? []).filter((f) => f.kind === 'folder').slice(0, 8)
  const fileCount = allItems ? allItems.filter((f) => f.kind === 'file').length : undefined
  const folderCount = allItems ? allItems.filter((f) => f.kind === 'folder').length : undefined

  const acts = activity.data
  const uploads = acts ? acts.filter((e) => e.action === 'upload') : undefined
  const downloads = acts ? acts.filter((e) => e.action === 'download') : undefined
  const timeline = [...(acts ?? [])].sort((a, b) => b.timestamp.localeCompare(a.timestamp)).slice(0, 6)

  // Rows come only from the backend listing; time is the backend's uploaded_at (no modified time is provided).
  const entries = recent.map((f) => ({
    id: f.id,
    icon: <FileIcon item={f} className="size-5" />,
    title: f.name,
    description: formatBytes(f.size_bytes),
    meta: formatRelative(f.uploaded_at, now),
  }))

  const hasQuota = p?.storage_used_bytes != null && p.storage_quota_bytes != null && p.storage_quota_bytes > 0

  return (
    <Stagger className="w-full">
      {offline && (
        <div
          role="status"
          className="mb-4 flex flex-wrap items-center gap-3 rounded-xl border border-sev-medium/25 bg-sev-medium/5 px-4 py-2.5 text-sm"
        >
          <PlugZap className="size-4 shrink-0 text-sev-medium" />
          <span className="flex-1 text-muted-foreground">
            <span className="font-medium text-foreground">Workspace offline.</span>{' '}
            {isApiConfigured
              ? 'The backend could not be reached - your files and activity will appear when it is back.'
              : 'Connect the VEYLIX backend to see your files, activity and storage.'}
          </span>
          {isApiConfigured && (
            <button onClick={retry} className="inline-flex items-center gap-1.5 text-xs text-cyan hover:underline">
              <RefreshCw className="size-3" /> Retry
            </button>
          )}
        </div>
      )}

      <FadeContent blur={false} duration={500}>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-12">
          {/* Hero: identity, primary action, headline numbers */}
          <BentoCard className="md:col-span-2 lg:col-span-8">
            <div className="flex flex-1 flex-col justify-between gap-8 p-6 sm:p-7">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div className="min-w-0">
                  <p className="text-[10px] font-medium uppercase tracking-[0.22em] text-cyan/80">
                    {p?.department ?? 'Employee workspace'}
                  </p>
                  <h1 className="mt-2 text-3xl font-semibold tracking-tight sm:text-4xl">
                    {profile.isLoading ? (
                      <Skeleton className="h-9 w-56" />
                    ) : p ? (
                      <>
                        Welcome back,
                        <br />
                        <span className="text-cyan">{p.display_name}</span>
                      </>
                    ) : (
                      <>
                        Your files,
                        <br />
                        <span className="text-muted-foreground">in one place.</span>
                      </>
                    )}
                  </h1>
                </div>
                <Link
                  to={routes.employee.upload}
                  aria-disabled={!isApiConfigured}
                  className={cn(
                    buttonVariants({ size: 'lg' }),
                    'shadow-[0_0_28px_-8px_var(--accent-cyan)]',
                    !isApiConfigured && 'pointer-events-none opacity-50 shadow-none',
                  )}
                >
                  <Upload className="size-4" /> Upload a file
                </Link>
              </div>

              <div className="grid grid-cols-2 divide-border sm:grid-cols-4 sm:divide-x">
                <Stat label="Files" value={fileCount} loading={files.isLoading} />
                <Stat label="Folders" value={folderCount} loading={files.isLoading} />
                <Stat
                  label="Uploads"
                  value={uploads?.length}
                  loading={activity.isLoading}
                  spark={uploads ? dailySeries(uploads.map((e) => e.timestamp), now) : null}
                />
                <Stat
                  label="Downloads"
                  value={downloads?.length}
                  loading={activity.isLoading}
                  spark={downloads ? dailySeries(downloads.map((e) => e.timestamp), now) : null}
                />
              </div>
            </div>
          </BentoCard>

          {/* Storage ring */}
          <BentoCard className="lg:col-span-4">
            <BentoHead eyebrow="Capacity" title="Storage" action={<HardDrive className="size-4 text-muted-foreground" />} />
            <div className="flex flex-1 flex-col items-center justify-center px-5 pb-6 pt-4">
              {profile.isLoading ? (
                <Skeleton className="size-40 rounded-full" />
              ) : hasQuota ? (
                <>
                  <StorageRing used={p!.storage_used_bytes!} quota={p!.storage_quota_bytes!} />
                  <p className="mt-4 text-sm text-muted-foreground">
                    <span className="font-medium text-foreground">{formatBytes(p!.storage_used_bytes)}</span> of{' '}
                    {formatBytes(p!.storage_quota_bytes)}
                  </p>
                </>
              ) : (
                <>
                  <div className="flex size-40 items-center justify-center rounded-full border-[10px] border-dashed border-raised">
                    <span className="text-2xl text-muted-foreground/50">–</span>
                  </div>
                  <p className="mt-4 text-center text-xs text-muted-foreground">
                    {offline ? 'Your usage appears here once connected.' : 'Storage details are not provided.'}
                  </p>
                </>
              )}
            </div>
          </BentoCard>

          {/* Recent files */}
          <BentoCard className="md:col-span-2 lg:col-span-7">
            <BentoHead
              eyebrow="Latest"
              title="Recent files"
              action={
                <Link to={routes.employee.files} className="inline-flex items-center gap-1 text-xs text-cyan hover:underline">
                  All files <ArrowUpRight className="size-3" />
                </Link>
              }
            />
            <div className="flex-1 p-3 pt-4">
              {files.isLoading ? (
                <ListSkeleton rows={4} />
              ) : entries.length > 0 ? (
                <AnimatedList
                  items={entries}
                  onItemSelect={(_, i) => navigate(`${routes.employee.files}?file=${encodeURIComponent(recent[i].id)}`)}
                  animation="fade"
                  animateOnce
                  stagger={0.03}
                  frame={false}
                  width="100%"
                  maxHeight={300}
                  gap={6}
                  radius={10}
                  accentColor="#0078D4"
                  theme="light"
                />
              ) : (
                <div className="px-2">
                  <GhostRows rows={3} />
                  <p className="mt-3 text-center text-xs text-muted-foreground">
                    {offline ? 'Recent files will appear here.' : 'No files yet - upload your first one to see it here.'}
                  </p>
                </div>
              )}
            </div>
          </BentoCard>

          {/* Activity timeline */}
          <BentoCard className="lg:col-span-5">
            <BentoHead eyebrow="Timeline" title="Recent activity" />
            <div className="flex-1 px-5 pb-5 pt-4">
              {activity.isLoading ? (
                <ListSkeleton rows={3} className="p-0" />
              ) : timeline.length > 0 ? (
                <ol className="relative space-y-4 border-l border-border pl-5">
                  {timeline.map((e) => (
                    <li key={e.id} className="relative">
                      <span
                        className={cn(
                          'absolute -left-[25px] top-1.5 size-2.5 rounded-full ring-4 ring-white',
                          RESULT_DOT[e.result],
                        )}
                      />
                      <div className="flex items-baseline justify-between gap-3">
                        <p className="min-w-0 truncate text-sm">
                          <span className="font-medium capitalize">{e.action}</span>
                          {e.file_name && <span className="text-muted-foreground"> · {e.file_name}</span>}
                        </p>
                        <time
                          dateTime={e.timestamp}
                          title={formatDateTime(e.timestamp)}
                          className="shrink-0 text-xs text-muted-foreground"
                        >
                          {formatRelative(e.timestamp, now)}
                        </time>
                      </div>
                      <p className="text-xs capitalize text-muted-foreground/80">{e.result}</p>
                    </li>
                  ))}
                </ol>
              ) : (
                <>
                  <GhostRows rows={3} />
                  <p className="mt-3 text-center text-xs text-muted-foreground">
                    {offline ? 'Your activity will appear here.' : 'No activity yet.'}
                  </p>
                </>
              )}
            </div>
          </BentoCard>

          {/* Shared folders */}
          <BentoCard className="md:col-span-2 lg:col-span-12">
            <BentoHead eyebrow="Workspaces" title="Shared folders" />
            <div className="p-5 pt-4">
              {files.isLoading ? (
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  {[0, 1, 2, 3].map((i) => (
                    <Skeleton key={i} className="h-20 rounded-xl" />
                  ))}
                </div>
              ) : folders.length > 0 ? (
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
                  {folders.map((f) => (
                    <Link
                      key={f.id}
                      to={`${routes.employee.files}?folder=${encodeURIComponent(f.id)}`}
                      className="group/tile relative flex items-center gap-3 rounded-xl border border-border bg-background/60 p-3.5 transition-all duration-200 hover:-translate-y-0.5 hover:border-cyan/40 hover:bg-raised/60"
                    >
                      <span className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-cyan/10 text-cyan transition-colors group-hover/tile:bg-cyan/20">
                        <FolderOpen className="size-5" />
                      </span>
                      <span className="min-w-0 flex-1 truncate text-sm font-medium">{f.name}</span>
                      <ArrowUpRight className="size-4 shrink-0 text-muted-foreground opacity-0 transition-opacity group-hover/tile:opacity-100" />
                    </Link>
                  ))}
                </div>
              ) : (
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-4" aria-hidden>
                  {[0, 1, 2, 3].map((i) => (
                    <div key={i} className="flex items-center gap-3 rounded-xl border border-dashed border-border/70 p-3.5">
                      <span className="size-10 rounded-lg bg-raised/70" />
                      <span className="h-2.5 w-1/2 rounded bg-raised/80" />
                    </div>
                  ))}
                </div>
              )}
              {!files.isLoading && folders.length === 0 && (
                <p className="mt-3 text-center text-xs text-muted-foreground">
                  {offline ? 'Folders you can access will appear here.' : 'No shared folders available to you yet.'}
                </p>
              )}
            </div>
          </BentoCard>
        </div>
      </FadeContent>
    </Stagger>
  )
}
