import { Navigate, Outlet, useLocation } from 'react-router-dom'
import { Loader2 } from 'lucide-react'
import { useAuth } from './AuthProvider'
import type { Role } from './auth.types'
import { homeFor, routes } from '@/lib/routes'
import { StateBlock } from '@/components/common/States'

/**
 * UI-preview mode: dev builds only, opt-in via VITE_UI_PREVIEW=true.
 * It renders the layouts WITHOUT a session so they can be reviewed. It is compiled out of
 * production builds (import.meta.env.DEV is false) and never marks anyone as authenticated.
 */
export const UI_PREVIEW = import.meta.env.DEV && import.meta.env.VITE_UI_PREVIEW === 'true'

/**
 * Client-side route guards are a UX convenience only. Authorization is enforced by the backend
 * on every request; these guards never grant access to data.
 */
export function RequireRole({ role }: { role: Role | Role[] }) {
  const allowed = Array.isArray(role) ? role : [role]
  const { status, user } = useAuth()
  const location = useLocation()

  if (UI_PREVIEW && !user) return <Outlet />
  if (status === 'loading') {
    return (
      <div className="flex min-h-screen items-center justify-center text-muted-foreground">
        <Loader2 className="size-5 animate-spin" aria-label="Checking session" />
      </div>
    )
  }
  if (status !== 'authenticated' || !user) {
    return <Navigate to={routes.login} replace state={{ from: location.pathname, reason: status }} />
  }
  if (!allowed.includes(user.role)) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <StateBlock
          tone="danger"
          title="Access denied"
          description="Your account does not have permission to view this area."
          action={
            <a className="text-xs text-cyan hover:underline" href={homeFor(user.role)}>
              Go to your workspace
            </a>
          }
        />
      </div>
    )
  }
  return <Outlet />
}
