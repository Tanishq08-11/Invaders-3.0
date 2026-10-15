import { useEffect, useState } from 'react'
import { useReducedMotion } from 'motion/react'

/** True only for the first ~0.8 s after a chart mounts, so refreshed data never replays the draw-in animation. */
export function useRevealOnce(ms = 800): boolean {
  const reduce = useReducedMotion()
  const [active, setActive] = useState(true)
  useEffect(() => {
    const t = window.setTimeout(() => setActive(false), ms)
    return () => window.clearTimeout(t)
  }, [ms])
  return active && !reduce
}
