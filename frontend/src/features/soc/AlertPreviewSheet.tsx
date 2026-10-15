import { Link } from 'react-router-dom'
import { ExternalLink } from 'lucide-react'
import { ScoringFailedBadge, SeverityBadge, StatusBadge } from '@/components/common/Badges'
import { buttonVariants } from '@/components/ui/button'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { formatDateTime } from '@/lib/format'
import { routes } from '@/lib/routes'
import { cn } from '@/lib/utils'
import type { Alert } from '@/types'

export function Signals({ alert, max = 2 }: { alert: Alert; max?: number }) {
  if (alert.signals.length === 0) return <span className="text-xs text-muted-foreground">None reported</span>
  return (
    <div className="flex flex-wrap gap-1">
      {alert.signals.slice(0, max).map((s) => (
        <span key={s.code} className="rounded bg-raised px-1.5 py-0.5 text-[11px] text-foreground/80">
          {s.label}
        </span>
      ))}
      {alert.signals.length > max && <span className="text-[11px] text-muted-foreground">+{alert.signals.length - max}</span>}
    </div>
  )
}

export function RiskCell({ alert }: { alert: Alert }) {
  if (alert.scoring_status === 'failed') return <ScoringFailedBadge />
  if (alert.risk_score == null) return <span className="text-xs text-muted-foreground">Unavailable</span>
  return <span className="font-mono text-sm font-medium">{Math.round(alert.risk_score)}</span>
}


/** Right-hand investigation preview used by the Alert Center and the SOC Overview. Esc / outside click close it. */
export function AlertPreviewSheet({ alert: selected, onClose }: { alert: Alert | null; onClose: () => void }) {
  return (
    <Sheet open={!!selected} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-full border-border bg-surface sm:max-w-md">
        {selected && (
          <>
            <SheetHeader>
              <SheetTitle className="font-mono">{selected.id}</SheetTitle>
              <SheetDescription>Alert preview</SheetDescription>
            </SheetHeader>
            <div className="space-y-4 px-4 text-sm">
              <div className="flex flex-wrap gap-2">
                <SeverityBadge severity={selected.severity} />
                <StatusBadge status={selected.status} />
              </div>
              <dl className="space-y-3">
                {[
                  ['Timestamp', formatDateTime(selected.created_at)],
                  ['Device', selected.device_id],
                  ['Source IP', selected.source_ip ?? 'Not reported'],
                  ['Destination', selected.destination ?? '—'],
                ].map(([k, v]) => (
                  <div key={k}>
                    <dt className="text-xs text-muted-foreground">{k}</dt>
                    <dd className="font-mono">{v}</dd>
                  </div>
                ))}
                <div>
                  <dt className="text-xs text-muted-foreground">Risk score</dt>
                  <dd>
                    <RiskCell alert={selected} />
                  </dd>
                </div>
                <div>
                  <dt className="mb-1 text-xs text-muted-foreground">Detection signals</dt>
                  <dd>
                    <Signals alert={selected} max={20} />
                  </dd>
                </div>
              </dl>
            </div>
            <div className="mt-auto flex flex-col gap-2 p-4">
              <Link to={routes.soc.alert(selected.id)} className={cn(buttonVariants(), 'w-full')}>
                Open full investigation <ExternalLink className="size-4" />
              </Link>
              <Link to={routes.soc.device(selected.device_id)} className={cn(buttonVariants({ variant: 'outline' }), 'w-full')}>
                Investigate device
              </Link>
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  )
}
