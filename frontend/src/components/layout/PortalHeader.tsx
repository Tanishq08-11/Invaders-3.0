import { useCallback, useState } from 'react'
import { Link, NavLink, useLocation, useNavigate } from 'react-router-dom'
import { Bell, BellOff, LogOut, Menu, Search, ShieldCheck, UserRound, type LucideIcon } from 'lucide-react'
import { AnimatedBackground } from '@/components/ui/animated-background'
import { Sheet, SheetContent, SheetDescription, SheetTitle, SheetTrigger } from '@/components/ui/sheet'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { Separator } from '@/components/ui/separator'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { CommandPalette, useCommandShortcut } from './CommandPalette'
import { useConnection, type ConnectionState } from '@/api/queries'
import { useAuth } from '@/auth/AuthProvider'
import { routes } from '@/lib/routes'
import { cn } from '@/lib/utils'

/** Notifications are not part of the agreed backend API yet; flip when an endpoint exists. */
const NOTIFICATIONS_SUPPORTED = false

export type PortalNavItem = { to: string; label: string; icon: LucideIcon }

const CONN: Record<ConnectionState, { label: string; hint: string; dot: string }> = {
  connected: { label: 'Connected', hint: 'Backend health check succeeded', dot: 'bg-green-600' },
  checking: { label: 'Checking', hint: 'Checking the backend connection', dot: 'bg-cyan' },
  disconnected: { label: 'Offline', hint: 'The backend is not responding', dot: 'bg-red-600' },
  not_configured: {
    label: 'Not configured',
    hint: 'No backend URL is configured (VITE_API_BASE_URL)',
    dot: 'bg-amber-500',
  },
}

function initials(name?: string | null): string | null {
  const parts = (name ?? '').trim().split(/\s+/).filter(Boolean)
  if (parts.length === 0) return null
  return (parts.length === 1 ? parts[0].slice(0, 2) : parts[0][0] + parts[parts.length - 1][0]).toUpperCase()
}

function Logo({ to, subtitle }: { to: string; subtitle: string }) {
  return (
    <Link to={to} className="flex shrink-0 items-center gap-2.5 rounded-lg outline-none focus-visible:ring-2 focus-visible:ring-cyan/50">
      <span className="flex size-8 items-center justify-center rounded-lg border border-cyan/40 bg-cyan/10 text-cyan">
        <ShieldCheck className="size-4.5" />
      </span>
      <span className="leading-tight">
        <span className="block text-sm font-semibold tracking-[0.18em]">VEYLIX</span>
        <span className="hidden text-[10px] text-muted-foreground lg:block">{subtitle}</span>
      </span>
    </Link>
  )
}

/** Sticky glass top navbar shared by the Employee and SOC portals: logo, route links (sliding pill), status, account. */
export function PortalHeader({
  nav,
  home,
  subtitle,
  label,
  profileTo,
  extra,
  deviceLookup,
}: {
  nav: PortalNavItem[]
  home: string
  subtitle: string
  label: string
  /** Account-menu "Profile" target; omitted when the portal has no profile page. */
  profileTo?: string
  /** Optional right-side controls rendered before the status pill (e.g. device lookup). */
  extra?: React.ReactNode
  /** Enables free-text device lookup inside the command palette (SOC). */
  deviceLookup?: boolean
}) {
  const { pathname } = useLocation()
  const navigate = useNavigate()
  const { state } = useConnection()
  const { user, logout } = useAuth()
  const [menuOpen, setMenuOpen] = useState(false)
  const [paletteOpen, setPaletteOpen] = useState(false)
  const togglePalette = useCallback(() => setPaletteOpen((o) => !o), [])
  useCommandShortcut(togglePalette)
  const signOut = () => void logout().finally(() => navigate(routes.login, { replace: true }))

  // Longest matching route wins so nested paths keep their parent highlighted.
  const activeTo = nav.filter((n) => pathname === n.to || pathname.startsWith(n.to + '/')).sort(
    (a, b) => b.to.length - a.to.length,
  )[0]?.to
  const conn = CONN[state]
  const ini = initials(user?.display_name)

  return (
    <header className="sticky top-0 z-40 border-b border-border bg-white/95 shadow-[0_6px_20px_-16px_rgba(0,90,158,0.35)] backdrop-blur-sm">
      <div className="mx-auto flex h-14 w-full items-center gap-3 px-4 sm:px-6 lg:px-8">
        {/* Mobile menu */}
        <Sheet open={menuOpen} onOpenChange={setMenuOpen}>
          <SheetTrigger
            aria-label="Open navigation"
            className="inline-flex size-9 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-accent hover:text-foreground md:hidden"
          >
            <Menu className="size-5" />
          </SheetTrigger>
          <SheetContent side="left" className="w-72">
            <SheetTitle className="sr-only">Navigation</SheetTitle>
            <SheetDescription className="sr-only">Portal pages</SheetDescription>
            <div className="p-4 pb-2">
              <Logo to={home} subtitle={subtitle} />
            </div>
            <nav aria-label={label} className="flex flex-col gap-1 p-3">
              {nav.map(({ to, label, icon: Icon }) => (
                <NavLink
                  key={to}
                  to={to}
                  end
                  onClick={() => setMenuOpen(false)}
                  className={cn(
                    'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition-colors',
                    to === activeTo
                      ? 'bg-cyan/10 text-foreground shadow-[inset_2px_0_0_var(--accent-cyan)]'
                      : 'text-muted-foreground hover:bg-accent hover:text-foreground',
                  )}
                >
                  <Icon className="size-4" />
                  {label}
                </NavLink>
              ))}
            </nav>
          </SheetContent>
        </Sheet>

        <Logo to={home} subtitle={subtitle} />

        {/* Desktop navigation, centered */}
        <nav aria-label={label} className="ml-2 hidden flex-1 md:flex">
          <div className="flex items-center gap-1">
            <AnimatedBackground
              defaultValue={activeTo}
              className="rounded-lg bg-cyan/10 shadow-[inset_0_-2px_0_var(--accent-cyan)]"
              transition={{ type: 'spring', bounce: 0.15, duration: 0.4 }}
            >
              {nav.map(({ to, label, icon: Icon }) => (
                <NavLink
                  key={to}
                  to={to}
                  end
                  data-id={to}
                  className={cn(
                    'rounded-lg px-3.5 py-2 text-[13px] font-medium transition-colors [&>.z-10]:flex [&>.z-10]:items-center [&>.z-10]:gap-2',
                    to === activeTo ? 'text-foreground' : 'text-muted-foreground hover:text-foreground',
                  )}
                >
                  <Icon className="size-4" />
                  {label}
                </NavLink>
              ))}
            </AnimatedBackground>
          </div>
        </nav>

        <div className="ml-auto flex items-center gap-1.5 sm:gap-2">
          {extra}
        <Tooltip>
          <TooltipTrigger
            render={
              <span
                role="status"
                className="inline-flex h-7 items-center gap-1.5 rounded-full border border-border bg-raised px-2.5 text-xs text-muted-foreground transition-colors hover:border-cyan/30 hover:text-foreground"
              />
            }
          >
            <span className="relative flex size-2 shrink-0 items-center justify-center" aria-hidden>
              {state === 'connected' && (
                <span className="absolute inline-flex size-full rounded-full bg-green-600/50 motion-safe:animate-[ping_3s_cubic-bezier(0,0,0.2,1)_infinite]" />
              )}
              <span className={cn('relative size-1.5 rounded-full', conn.dot, state === 'checking' && 'motion-safe:animate-pulse')} />
            </span>
            <span className="hidden md:inline">{conn.label}</span>
            <span className="sr-only md:hidden">{conn.label}</span>
          </TooltipTrigger>
          <TooltipContent>{conn.hint}</TooltipContent>
        </Tooltip>

        <button
          type="button"
          onClick={() => setPaletteOpen(true)}
          aria-label="Open command palette"
          className="inline-flex h-8 items-center gap-2 rounded-lg border border-border bg-raised px-2 text-xs text-muted-foreground transition-colors hover:border-cyan/30 hover:text-foreground focus-visible:outline-2 focus-visible:outline-cyan"
        >
          <Search className="size-3.5" />
          <span className="hidden lg:inline">Search</span>
          <kbd className="hidden rounded border border-border bg-card px-1 font-mono text-[10px] lg:inline">Ctrl K</kbd>
        </button>

        <Popover>
          <PopoverTrigger
            aria-label="Notifications"
            className="relative inline-flex size-8 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-2 focus-visible:outline-cyan"
          >
            <Bell className="size-4" />
          </PopoverTrigger>
          <PopoverContent align="end" className="w-80 p-0">
            <div className="flex items-center justify-between border-b border-border px-4 py-3">
              <p className="text-sm font-semibold">Notifications</p>
              <span className="text-[11px] text-muted-foreground">{NOTIFICATIONS_SUPPORTED ? 'Unread: 0' : 'Unavailable'}</span>
            </div>
            <div className="flex flex-col items-center gap-2 px-6 py-10 text-center">
              <span className="flex size-10 items-center justify-center rounded-full border border-border bg-raised text-muted-foreground">
                <BellOff className="size-5" />
              </span>
              <p className="text-sm font-medium">Notifications are not available yet</p>
              <p className="text-xs leading-relaxed text-muted-foreground">
                The backend does not provide a notification service, so nothing is shown here instead of placeholder alerts.
              </p>
            </div>
          </PopoverContent>
        </Popover>

        <Separator orientation="vertical" className="mx-0.5 data-vertical:h-5 data-vertical:self-center" />

        {user ? (
          <DropdownMenu>
            <DropdownMenuTrigger
              aria-label="Account menu"
              className="flex items-center gap-2 rounded-full p-0.5 outline-none transition-colors hover:bg-accent focus-visible:ring-2 focus-visible:ring-cyan/50 sm:pr-2.5"
            >
              <Avatar size="sm" className="size-7">
                <AvatarFallback className="bg-cyan/15 text-[11px] font-semibold text-cyan">
                  {ini ?? <UserRound className="size-3.5" />}
                </AvatarFallback>
              </Avatar>
              <span className="hidden max-w-32 truncate text-[13px] sm:inline">{user.display_name}</span>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56">
              <DropdownMenuGroup>
                <DropdownMenuLabel className="flex flex-col gap-0.5 px-2 py-1.5">
                  <span className="truncate text-sm font-medium text-foreground">{user.display_name}</span>
                  {(user.email ?? user.department) && (
                    <span className="truncate text-xs font-normal text-muted-foreground">
                      {user.email ?? user.department}
                    </span>
                  )}
                </DropdownMenuLabel>
              </DropdownMenuGroup>
              <DropdownMenuSeparator />
              {profileTo && (
                <DropdownMenuItem onClick={() => navigate(profileTo)}>
                  <UserRound className="size-4" />
                  Profile
                </DropdownMenuItem>
              )}
              <DropdownMenuItem
                variant="destructive"
                onClick={signOut}
              >
                <LogOut className="size-4" />
                Log out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        ) : (
          <Tooltip>
            <TooltipTrigger
              render={
                <span
                  aria-label="Not signed in"
                  className="inline-flex size-7 items-center justify-center rounded-full border border-dashed border-border text-muted-foreground"
                />
              }
            >
              <UserRound className="size-3.5" />
            </TooltipTrigger>
            <TooltipContent>No signed-in session</TooltipContent>
          </Tooltip>
        )}
        </div>
      </div>
      <CommandPalette
        open={paletteOpen}
        onOpenChange={setPaletteOpen}
        nav={nav}
        groupLabel={subtitle}
        profileTo={profileTo}
        deviceLookup={deviceLookup}
        signedIn={!!user}
        onLogout={signOut}
      />
    </header>
  )
}
