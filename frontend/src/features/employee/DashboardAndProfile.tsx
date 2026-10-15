import { useProfile } from '@/api/files'
import { ApiError, isApiConfigured } from '@/api/client'
import { PageHeader, Panel } from '@/components/common/Panel'
import { ErrorState, Unavailable } from '@/components/common/States'
import { Skeleton } from '@/components/ui/skeleton'
import { formatBytes } from '@/lib/format'

function Storage({ used, quota }: { used?: number | null; quota?: number | null }) {
  if (used == null || quota == null || quota <= 0) return <Unavailable>Storage information is not provided by the backend.</Unavailable>
  const pct = Math.min(100, (used / quota) * 100)
  return (
    <div>
      <div className="h-2 overflow-hidden rounded-full bg-raised">
        <div className="h-full bg-cyan" style={{ width: `${pct}%` }} />
      </div>
      <p className="mt-2 text-xs text-muted-foreground">
        {formatBytes(used)} of {formatBytes(quota)} used
      </p>
    </div>
  )
}

export function ProfilePage() {
  const { data: p, isLoading, isError, error, refetch } = useProfile()
  return (
    <div>
      <PageHeader title="Profile" description="Account details as recorded by the backend." />
      {isLoading ? (
        <Skeleton className="h-40 w-full" />
      ) : isError || !isApiConfigured || !p ? (
        <Panel>
          <ErrorState compact error={error ?? new ApiError('not_configured', '')} onRetry={() => void refetch()} />
        </Panel>
      ) : (
        <div className="grid gap-4 lg:grid-cols-3">
          <Panel title="Account" subtitle="Identity as recorded by the backend" className="lg:col-span-2">
            <dl className="grid gap-x-8 gap-y-4 text-sm sm:grid-cols-2">
              {[
                ['Name', p.display_name],
                ['Employee ID', p.username],
                ['Email', p.email],
              ].map(([k, v]) => (
                <div key={k as string} className="min-w-0">
                  <dt className="text-xs uppercase tracking-wider text-muted-foreground">{k}</dt>
                  <dd className="mt-1 truncate font-medium">{v ?? 'Not provided'}</dd>
                </div>
              ))}
            </dl>
          </Panel>
          <Panel title="Department & role" subtitle="Access is assigned by your organisation">
            <dl className="space-y-4 text-sm">
              {[
                ['Department', p.department],
                ['Role', p.role === 'SECURITY_ANALYST' ? 'Security Analyst' : 'Employee'],
              ].map(([k, v]) => (
                <div key={k as string} className="min-w-0">
                  <dt className="text-xs uppercase tracking-wider text-muted-foreground">{k}</dt>
                  <dd className="mt-1 truncate font-medium">{v ?? 'Not provided'}</dd>
                </div>
              ))}
            </dl>
          </Panel>
          <Panel title="Storage" subtitle="Quota reported by the backend" className="lg:col-span-3">
            <Storage used={p.storage_used_bytes} quota={p.storage_quota_bytes} />
          </Panel>
        </div>
      )}
    </div>
  )
}
