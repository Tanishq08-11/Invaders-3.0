import { Toaster } from 'sonner'
import { Activity, FolderOpen, Home, Upload, UserRound } from 'lucide-react'
import { PortalBackground } from './PortalBackground'
import { PageTransition } from './PageTransition'
import { PortalHeader, type PortalNavItem } from './PortalHeader'
import { routes } from '@/lib/routes'
import { useAuth } from '@/auth/AuthProvider'
import { UI_PREVIEW } from '@/auth/guards'

const NAV: PortalNavItem[] = [
  { to: routes.employee.dashboard, label: 'Dashboard', icon: Home },
  { to: routes.employee.files, label: 'Files', icon: FolderOpen },
  { to: routes.employee.upload, label: 'Upload', icon: Upload },
  { to: routes.employee.activity, label: 'Activity', icon: Activity },
  { to: routes.employee.profile, label: 'Profile', icon: UserRound },
]

/** Employee portal layout: sticky top navbar and full-width content (no sidebar). */
export function EmployeeShell() {
  const { user } = useAuth()

  return (
    <div className="relative flex min-h-svh flex-col overflow-x-clip bg-background">
      <PortalBackground />
      <div className="sticky top-0 z-40 flex flex-col">
        {UI_PREVIEW && !user && (
          <div className="border-b border-sev-medium/20 bg-sev-medium/10 px-4 py-1 text-center text-[11px] truncate text-sev-medium">
            Preview mode - not signed in. No data until a backend session exists.
          </div>
        )}
        <PortalHeader
          nav={NAV}
          home={routes.employee.dashboard}
          subtitle="Employee Portal"
          label="Employee portal"
          profileTo={routes.employee.profile}
        />
      </div>
      <main className="relative z-10 flex-1 px-4 py-6 sm:px-6 lg:px-8">
        <div className="mx-auto w-full max-w-[2200px] lg:w-[95%]">
          <PageTransition />
        </div>
      </main>
      <Toaster theme="light" position="bottom-right" richColors />
    </div>
  )
}
