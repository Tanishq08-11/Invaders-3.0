import { SEVERITY_COLOR } from '@/lib/severity'
import type { Severity } from '@/types'

interface Props {
  score?: number | null
  severity?: Severity
  size?: number
}

/** Semi-circular risk gauge. A missing score renders as "unavailable", never as 0. */
export function ScoreGauge({ score, severity, size = 180 }: Props) {
  const available = score != null && Number.isFinite(score)
  const pct = available ? Math.max(0, Math.min(100, score)) / 100 : 0
  const color = available && severity ? SEVERITY_COLOR[severity] : '#94A3B8'
  const r = 70
  const c = Math.PI * r
  return (
    <div className="flex flex-col items-center" style={{ width: size }}>
      <svg viewBox="0 0 180 105" width={size} role="img" aria-label={available ? `Risk score ${score} out of 100` : 'Risk score unavailable'}>
        <path d="M20 90 A70 70 0 0 1 160 90" fill="none" stroke="#DCE8F5" strokeWidth="12" strokeLinecap="round" />
        {available && (
          <path
            d="M20 90 A70 70 0 0 1 160 90"
            fill="none"
            stroke={color}
            strokeWidth="12"
            strokeLinecap="round"
            strokeDasharray={`${c * pct} ${c}`}
            style={{ transition: 'stroke-dasharray 600ms ease-out', filter: `drop-shadow(0 0 6px ${color}66)` }}
          />
        )}
        <text x="90" y={available ? 82 : 78} textAnchor="middle" className="fill-foreground" fontSize={available ? 34 : 13} fontWeight="600">
          {available ? Math.round(score) : 'Unavailable'}
        </text>
        {available && (
          <text x="90" y="100" textAnchor="middle" className="fill-muted-foreground" fontSize="10">
            RISK SCORE / 100
          </text>
        )}
      </svg>
    </div>
  )
}
