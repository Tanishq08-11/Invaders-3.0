import { useRef } from 'react'
import { motion, useReducedMotion, type Variants } from 'motion/react'
import { cn } from '@/lib/utils'

/** Staggered entrance: 0.1 s between cards, each fades in and slides up 20 px over 0.4 s, once on mount. */
export const staggerContainer: Variants = {
  hidden: {},
  show: { transition: { staggerChildren: 0.1 } },
}
export const staggerItem: Variants = {
  hidden: { opacity: 0, y: 20 },
  show: { opacity: 1, y: 0, transition: { duration: 0.4, ease: 'easeOut' } },
}

/**
 * Wrap a page's cards in <Stagger>: every BentoCard / Panel inside it enters in DOM order.
 * Plays once per mount (no replays, no scroll triggers); skipped entirely for reduced motion.
 */
export function Stagger({ className, children }: { className?: string; children: React.ReactNode }) {
  const reduce = useReducedMotion()
  return (
    <motion.div className={className} variants={staggerContainer} initial={reduce ? false : 'hidden'} animate="show">
      {children}
    </motion.div>
  )
}

/**
 * Bento surface: layered gradient, inner highlight rim and a soft cyan light that follows the cursor
 * (a single passive pointermove handler that only writes two CSS variables - no animation loop).
 */
export function BentoCard({
  className,
  children,
  as = 'section',
}: {
  className?: string
  children: React.ReactNode
  as?: 'section' | 'div'
}) {
  const Tag = as === 'div' ? motion.div : motion.section
  const ref = useRef<HTMLElement>(null)
  const onMove = (e: React.PointerEvent) => {
    const el = ref.current
    if (!el) return
    const r = el.getBoundingClientRect()
    el.style.setProperty('--bx', `${e.clientX - r.left}px`)
    el.style.setProperty('--by', `${e.clientY - r.top}px`)
  }
  return (
    <Tag
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      ref={ref as any}
      onPointerMove={onMove}
      variants={staggerItem}
      className={cn(
        // Frosted glass: translucent layered fill + static blur (never animated) + soft cyan edge.
        'group/bento relative overflow-hidden rounded-2xl border border-border bg-card',
        'shadow-[0_1px_2px_rgba(16,42,67,0.04),0_14px_34px_-20px_rgba(0,120,212,0.22)] transition-[border-color,box-shadow,transform] duration-200',
        'hover:-translate-y-0.5 hover:border-[#93C5FD] hover:shadow-[0_1px_2px_rgba(16,42,67,0.05),0_20px_40px_-20px_rgba(0,120,212,0.32)]',
        className,
      )}
    >
      <span
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-0 transition-opacity duration-300 group-hover/bento:opacity-100"
        style={{
          background:
            'radial-gradient(280px circle at var(--bx, 50%) var(--by, 50%), rgba(0,120,212,0.07), transparent 70%)',
        }}
      />
      <span aria-hidden className="pointer-events-none absolute inset-0 rounded-[inherit] shadow-none" />
      {/* cyan top-edge highlight */}
      <span aria-hidden className="pointer-events-none absolute inset-x-6 top-0 h-px bg-gradient-to-r from-transparent via-cyan/40 to-transparent" />
      <div className="relative flex h-full flex-col">{children}</div>
    </Tag>
  )
}

export function BentoHead({
  eyebrow,
  title,
  action,
}: {
  eyebrow?: string
  title: string
  action?: React.ReactNode
}) {
  return (
    <header className="flex items-start justify-between gap-3 px-5 pt-5">
      <div>
        {eyebrow && <p className="text-[10px] font-medium uppercase tracking-[0.2em] text-cyan/80">{eyebrow}</p>}
        <h2 className="mt-0.5 text-base font-semibold tracking-tight">{title}</h2>
      </div>
      {action}
    </header>
  )
}

/** Static, calm placeholder rows used when there is nothing real to show yet. */
export function GhostRows({ rows = 3, className }: { rows?: number; className?: string }) {
  return (
    <div aria-hidden className={cn('space-y-2.5', className)}>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center gap-3 rounded-xl border border-dashed border-border/70 px-3 py-2.5">
          <span className="size-8 rounded-lg bg-raised/70" />
          <span className="flex-1 space-y-1.5">
            <span className="block h-2.5 rounded bg-raised/80" style={{ width: `${70 - i * 12}%` }} />
            <span className="block h-2 w-1/4 rounded bg-raised/50" />
          </span>
        </div>
      ))}
    </div>
  )
}

/** Minimal sparkline; callers must only render it for real historical values. */
export function Sparkline({ values, className }: { values: number[]; className?: string }) {
  if (values.length < 2) return null
  const w = 72
  const h = 22
  const max = Math.max(...values, 1)
  const pts = values.map((v, i) => `${((i / (values.length - 1)) * w).toFixed(1)},${(h - 2 - (v / max) * (h - 4)).toFixed(1)}`)
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className={cn('h-5 w-[72px] overflow-visible', className)} aria-hidden>
      <polyline points={pts.join(' ')} fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}
