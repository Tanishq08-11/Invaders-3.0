import { Outlet, useLocation } from 'react-router-dom'
import { motion, useReducedMotion } from 'motion/react'

/** Fades and lifts route content in (8 px, 0.2 s). Only the routed content animates; the navbar stays put. */
export function PageTransition() {
  const { pathname } = useLocation()
  const reduce = useReducedMotion()
  return (
    <motion.div
      key={pathname}
      initial={reduce ? false : { opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2, ease: 'easeOut' }}
    >
      <Outlet />
    </motion.div>
  )
}
