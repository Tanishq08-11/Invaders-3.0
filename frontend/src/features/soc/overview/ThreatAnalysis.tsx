import { Activity, Clock, Globe2, Waves, type LucideIcon } from 'lucide-react'
import { Panel } from '@/components/common/Panel'
import { StateBlock } from '@/components/common/States'
import { Progress } from '@/components/ui/progress'
import { SEVERITY_ORDER } from '@/lib/format'
import { SEVERITY_COLOR, SEVERITY_LABEL } from '@/lib/severity'
import type { Alert, Severity } from '@/types'

interface Indicator {
  key: string
  title: string
  hint: string
  icon: LucideIcon
  match: RegExp
}

// Matched against the signal codes/labels the backend attaches to each alert.
const INDICATORS: Indicator[] = [
  { key: 'volume', title: 'Outbound volume anomaly', hint: 'Unusual amount of data sent out', icon: Activity, match: /volume|bytes|outbound|upload|transfer|size/i },
  { key: 'destination', title: 'Destination novelty', hint: 'Destinations not seen in the device baseline', icon: Globe2, match: /destination|novel|new_dest|rare|first_seen|unseen/i },
  { key: 'time', title: 'Unusual activity time', hint: 'Activity outside typical hours', icon: Clock, match: /time|hour|off_hours|after_hours|schedule/i },
  { key: 'burst', title: 'Connection burst / traffic pattern', hint: 'Bursts or irregular connection patterns', icon: Waves, match: /burst|connection|frequency|pattern|rate|beacon/i },
]

/**
 * Prevalence of each signal family across the alerts the backend returned. These are counts of alerts carrying a
 * matching reported signal - not model probabilities, not anomaly scores, and not confirmation of data loss.
 */
export function ThreatAnalysis({ alerts }: { alerts: Alert[] }) {
  const total = alerts.length
  const anySignals = alerts.some((a) => a.signals.length > 0)

  return (
    <Panel title="Threat analysis" subtitle="Share of received alerts carrying each reported signal type" className="xl:col-span-2">
      {total === 0 ? (
        <StateBlock compact title="No alerts to analyse" description="Signal analysis appears once alerts are received." />
      ) : !anySignals ? (
        <StateBlock compact title="No signal data reported" description="The received alerts do not include signal details." />
      ) : (
        <ul className="grid gap-4 sm:grid-cols-2">
          {INDICATORS.map((ind) => {
            const hit = alerts.filter((a) => a.signals.some((s) => ind.match.test(s.code) || ind.match.test(s.label)))
            const pct = (hit.length / total) * 100
            const top = hit.reduce<Severity | null>(
              (acc, a) => (acc === null || SEVERITY_ORDER[a.severity] > SEVERITY_ORDER[acc] ? a.severity : acc),
              null,
            )
            const Icon = ind.icon
            return (
              <li key={ind.key} className="rounded-xl border border-border bg-raised p-4">
                <div className="flex items-start gap-3">
                  <span className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-cyan/25 bg-cyan/10 text-cyan">
                    <Icon className="size-4" />
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium">{ind.title}</p>
                    <p className="text-xs text-muted-foreground">{ind.hint}</p>
                  </div>
                  {top && (
                    <span className="mt-0.5 inline-flex shrink-0 items-center gap-1.5 text-[11px] text-muted-foreground" title="Highest severity among matching alerts">
                      <span className="size-2 rounded-full" style={{ background: SEVERITY_COLOR[top] }} />
                      {SEVERITY_LABEL[top]}
                    </span>
                  )}
                </div>
                <Progress value={pct} aria-label={`${ind.title}: ${hit.length} of ${total} alerts`} className="mt-3" />
                <p className="mt-2 text-xs text-muted-foreground">{hit.length === 0 ? 'No alerts carry this signal' : `${hit.length} of ${total} alerts`}</p>
              </li>
            )
          })}
        </ul>
      )}
    </Panel>
  )
}
