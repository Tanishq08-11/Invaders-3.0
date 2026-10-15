import { useRef, type ReactNode } from 'react'
import { AnimatePresence, motion, useReducedMotion } from 'motion/react'
import { cn } from '@/lib/utils'

interface AnimatedListProps<T> {
  items: T[]
  getKey: (item: T) => string
  render: (item: T) => ReactNode
  className?: string
}

/**
 * Magic UI animated list, adapted for live data: the first batch renders without animation and
 * only entries whose key has not been seen before animate in (once). Order is the caller's.
 */
export function AnimatedList<T>({ items, getKey, render, className }: AnimatedListProps<T>) {
  const reduced = useReducedMotion()
  const seen = useRef<Set<string> | null>(null)
  const isFirstBatch = seen.current === null
  if (seen.current === null) seen.current = new Set()

  const fresh = new Set<string>()
  for (const item of items) {
    const k = getKey(item)
    if (!seen.current.has(k)) {
      if (!isFirstBatch) fresh.add(k)
      seen.current.add(k)
    }
  }

  return (
    <ul className={cn('flex flex-col', className)}>
      <AnimatePresence initial={false}>
        {items.map((item) => {
          const k = getKey(item)
          const animate = !reduced && fresh.has(k)
          return (
            <motion.li
              key={k}
              layout={!reduced}
              initial={animate ? { scale: 0.9, opacity: 0, y: -8 } : false}
              animate={{ scale: 1, opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              transition={{ type: 'spring', stiffness: 350, damping: 40 }}
            >
              {render(item)}
            </motion.li>
          )
        })}
      </AnimatePresence>
    </ul>
  )
}
