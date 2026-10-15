import { motion } from 'motion/react'
import { cn } from '@/lib/utils'
import { staggerItem } from './Bento'

interface PanelProps {
  title?: string
  subtitle?: string
  action?: React.ReactNode
  className?: string
  bodyClassName?: string
  children: React.ReactNode
}

export function Panel({ title, subtitle, action, className, bodyClassName, children }: PanelProps) {
  return (
    <motion.section
      variants={staggerItem}
      className={cn(
        'relative overflow-hidden rounded-2xl border border-border bg-card',
        'shadow-[0_1px_2px_rgba(16,42,67,0.04),0_14px_34px_-22px_rgba(0,120,212,0.2)] transition-[border-color,box-shadow] duration-200 hover:border-[#93C5FD]',
        className,
      )}
    >
      {(title || action) && (
        <header className="flex items-start justify-between gap-3 border-b border-border px-4 py-3">
          <div className="min-w-0">
            {title && <h2 className="text-sm font-semibold tracking-tight">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-xs text-muted-foreground">{subtitle}</p>}
          </div>
          {action}
        </header>
      )}
      <div className={cn('p-4', bodyClassName)}>{children}</div>
    </motion.section>
  )
}

export function PageHeader({
  title,
  description,
  actions,
  back,
}: {
  title: string
  description?: string
  actions?: React.ReactNode
  back?: React.ReactNode
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        {back}
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {description && <p className="mt-1 max-w-2xl text-sm text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}
