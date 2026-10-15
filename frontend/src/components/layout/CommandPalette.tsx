import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { CornerDownLeft, LogOut, MonitorSmartphone, SearchX, UserRound } from 'lucide-react'
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from '@/components/ui/command'
import { routes } from '@/lib/routes'
import type { PortalNavItem } from './PortalHeader'

/** Ctrl/Cmd+K listener; kept separate so the dialog itself only mounts content when opened. */
export function useCommandShortcut(toggle: () => void) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        toggle()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [toggle])
}

/**
 * Global command palette. Lists only the routes of the portal the signed-in user is in (each portal is already
 * role-guarded by the router), so nothing unauthorised is ever offered.
 */
export function CommandPalette({
  open,
  onOpenChange,
  nav,
  groupLabel,
  profileTo,
  deviceLookup,
  onLogout,
  signedIn,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  nav: PortalNavItem[]
  groupLabel: string
  profileTo?: string
  deviceLookup?: boolean
  onLogout: () => void
  signedIn: boolean
}) {
  const navigate = useNavigate()
  const [query, setQuery] = useState('')

  const go = (to: string) => {
    onOpenChange(false)
    setQuery('')
    navigate(to)
  }
  const deviceId = query.trim()

  return (
    <CommandDialog
      open={open}
      onOpenChange={(o) => {
        onOpenChange(o)
        if (!o) setQuery('')
      }}
      title="Command palette"
      description="Search pages and actions"
    >
      <CommandInput value={query} onValueChange={setQuery} placeholder="Search pages and actions…" />
      <CommandList>
        <CommandEmpty>
          <span className="flex flex-col items-center gap-2 py-4 text-muted-foreground">
            <SearchX className="size-5" />
            <span className="text-sm">No results for “{query}”</span>
            <span className="text-xs">Try a page name such as “Files” or “Alerts”.</span>
          </span>
        </CommandEmpty>

        <CommandGroup heading={groupLabel}>
          {nav.map(({ to, label, icon: Icon }) => (
            <CommandItem key={to} value={`${label} ${to}`} onSelect={() => go(to)}>
              <Icon className="size-4" />
              {label}
            </CommandItem>
          ))}
          {profileTo && !nav.some((n) => n.to === profileTo) && (
            <CommandItem value="Profile account" onSelect={() => go(profileTo)}>
              <UserRound className="size-4" />
              Profile
            </CommandItem>
          )}
        </CommandGroup>

        {deviceLookup && deviceId && (
          <>
            <CommandSeparator />
            <CommandGroup heading="Investigate">
              <CommandItem forceMount value={`investigate device ${deviceId}`} onSelect={() => go(routes.soc.device(deviceId))}>
                <MonitorSmartphone className="size-4" />
                <span className="truncate">
                  Investigate device <span className="font-mono">{deviceId}</span>
                </span>
                <CornerDownLeft className="ml-auto size-3.5 opacity-50" />
              </CommandItem>
            </CommandGroup>
          </>
        )}

        {signedIn && (
          <>
            <CommandSeparator />
            <CommandGroup heading="Account">
              <CommandItem
                value="log out sign out"
                onSelect={() => {
                  onOpenChange(false)
                  onLogout()
                }}
              >
                <LogOut className="size-4" />
                Log out
              </CommandItem>
            </CommandGroup>
          </>
        )}
      </CommandList>
    </CommandDialog>
  )
}
