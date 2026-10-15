import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { LayoutDashboard, Search, ShieldAlert } from 'lucide-react'
import { Toaster } from 'sonner'
import { Input } from '@/components/ui/input'
import { PortalBackground } from './PortalBackground'
import { PageTransition } from './PageTransition'
import { PortalHeader, type PortalNavItem } from './PortalHeader'
import { useAuth } from '@/auth/AuthProvider'
import { UI_PREVIEW } from '@/auth/guards'
import { routes } from '@/lib/routes'

const NAV: PortalNavItem[] = [
  { to: routes.soc.overview, label: 'Security Overview', icon: LayoutDashboard },
  { to: routes.soc.alerts, label: 'Alert Center', icon: ShieldAlert },
]

/** SOC layout for security analysts: sticky top navbar with device lookup, full-width content. */
export function SocShell() {
  const navigate = useNavigate()
  const { user } = useAuth()
  const [device, setDevice] = useState('')

  return (
    <div className="relative flex min-h-svh flex-col overflow-x-clip bg-background">
      <PortalBackground />
      <div className="sticky top-0 z-40 flex flex-col">
        {UI_PREVIEW && !user && (
          <div className="truncate border-b border-sev-medium/20 bg-sev-medium/10 px-4 py-1 text-center text-[11px] text-sev-medium">
            Preview mode - not signed in. No data until a backend session exists.
          </div>
        )}
        <PortalHeader
          nav={NAV}
          home={routes.soc.overview}
          subtitle="Security Operations"
          label="Security operations"
          deviceLookup
          extra={
            <form
              className="hidden lg:block"
              onSubmit={(e) => {
                e.preventDefault()
                const id = device.trim()
                if (!id) return
                navigate(routes.soc.device(id))
                setDevice('')
              }}
            >
              <div className="relative">
                <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={device}
                  onChange={(e) => setDevice(e.target.value)}
                  aria-label="Investigate device"
                  placeholder="Investigate device"
                  className="h-8 w-48 bg-background/60 pl-8 font-mono text-xs"
                />
              </div>
            </form>
          }
        />
      </div>
      <main className="relative z-10 flex-1 px-4 py-6 sm:px-6 lg:px-8">
        <PageTransition />
      </main>
      <Toaster theme="light" position="bottom-right" richColors />
    </div>
  )
}
