import { useEffect, useRef, type ComponentPropsWithoutRef } from 'react'
import { useInView, useMotionValue, useReducedMotion, useSpring } from 'motion/react'
import { cn } from '@/lib/utils'

interface NumberTickerProps extends ComponentPropsWithoutRef<'span'> {
  value: number
  startValue?: number
  delay?: number
  decimalPlaces?: number
}

/** Counts up to `value` when scrolled into view (Magic UI number ticker). Snaps instantly for reduced motion. */
export function NumberTicker({ value, startValue = 0, delay = 0, decimalPlaces = 0, className, ...props }: NumberTickerProps) {
  const ref = useRef<HTMLSpanElement>(null)
  const reduced = useReducedMotion()
  const motionValue = useMotionValue(startValue)
  const springValue = useSpring(motionValue, { damping: 60, stiffness: 100 })
  const isInView = useInView(ref, { once: true, margin: '0px' })
  const format = (n: number) =>
    Intl.NumberFormat('en-US', { minimumFractionDigits: decimalPlaces, maximumFractionDigits: decimalPlaces }).format(n)

  useEffect(() => {
    if (!isInView) return
    if (reduced) {
      if (ref.current) ref.current.textContent = format(value)
      return
    }
    const timer = setTimeout(() => motionValue.set(value), delay * 1000)
    return () => clearTimeout(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [motionValue, isInView, delay, value, reduced])

  useEffect(
    () =>
      springValue.on('change', (latest) => {
        if (ref.current && !reduced) ref.current.textContent = format(Number(latest.toFixed(decimalPlaces)))
      }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [springValue, decimalPlaces, reduced],
  )

  return (
    <span ref={ref} className={cn('inline-block tabular-nums', className)} {...props}>
      {format(startValue)}
    </span>
  )
}
