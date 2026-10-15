import { AlertTriangle, FileQuestion, Inbox, LockKeyhole, PlugZap, ServerCrash, WifiOff } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { ApiError } from '@/api/client'

interface StateBlockProps {
  icon?: React.ReactNode
  title: string
  description?: string
  tone?: 'neutral' | 'warning' | 'danger'
  action?: React.ReactNode
  compact?: boolean
  className?: string
}

const TONE = { neutral: 'text-muted-foreground', warning: 'text-sev-medium', danger: 'text-sev-critical' }

export function StateBlock({ icon, title, description, tone = 'neutral', action, compact, className }: StateBlockProps) {
  return (
    <div
      role="status"
      className={cn(
        'flex flex-col items-center justify-center text-center',
        compact ? 'gap-2 px-4 py-8' : 'gap-3 px-6 py-14',
        className,
      )}
    >
      <div className={cn('flex size-10 items-center justify-center rounded-full border border-border bg-raised', TONE[tone])}>
        {icon ?? <Inbox className="size-5" />}
      </div>
      <p className="text-sm font-medium">{title}</p>
      {description && <p className="max-w-sm text-xs leading-relaxed text-muted-foreground">{description}</p>}
      {action}
    </div>
  )
}

/** Maps any failed request to an honest, specific state - never to zero values. */
export function ErrorState({ error, onRetry, compact }: { error: unknown; onRetry?: () => void; compact?: boolean }) {
  const retry = onRetry && (
    <Button variant="outline" size="sm" onClick={onRetry}>
      Retry
    </Button>
  )
  if (error instanceof ApiError) {
    switch (error.kind) {
      case 'not_configured':
        return (
          <StateBlock
            compact={compact}
            tone="warning"
            icon={<PlugZap className="size-5" />}
            title="Awaiting backend connection"
            description="No backend URL is configured. Set VITE_API_BASE_URL to connect to the detection service."
          />
        )
      case 'network':
        return (
          <StateBlock
            compact={compact}
            tone="danger"
            icon={<WifiOff className="size-5" />}
            title="Backend disconnected"
            description="The detection service could not be reached. No data is being shown."
            action={retry}
          />
        )
      case 'invalid_response':
        return (
          <StateBlock
            compact={compact}
            tone="danger"
            icon={<AlertTriangle className="size-5" />}
            title="Unexpected backend response"
            description="The response did not match the expected contract, so it was not displayed."
            action={retry}
          />
        )
      case 'http':
        if (error.status === 401 || error.status === 403)
          return (
            <StateBlock
              compact={compact}
              tone="warning"
              icon={<LockKeyhole className="size-5" />}
              title={error.status === 401 ? 'Sign-in required' : 'Permission denied'}
              description={
                error.status === 401
                  ? 'Your session is missing or has expired. Sign in again to continue.'
                  : 'Your account is not permitted to view this data. Contact an administrator if you need access.'
              }
            />
          )
        if (error.status === 404)
          return (
            <StateBlock
              compact={compact}
              icon={<FileQuestion className="size-5" />}
              title="Record not found"
              description="The backend has no record with this identifier."
            />
          )
        return (
          <StateBlock
            compact={compact}
            tone="danger"
            icon={<ServerCrash className="size-5" />}
            title={`Backend error${error.status ? ` (${error.status})` : ''}`}
            description={error.message}
            action={retry}
          />
        )
    }
  }
  return (
    <StateBlock
      compact={compact}
      tone="danger"
      icon={<AlertTriangle className="size-5" />}
      title="Something went wrong"
      description="An unexpected error occurred while loading this data."
      action={retry}
    />
  )
}

export function Unavailable({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-dashed border-border bg-background/40 px-4 py-6 text-center text-xs text-muted-foreground">
      {children}
    </div>
  )
}
