import { useState } from 'react'
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom'
import { motion, MotionConfig } from 'motion/react'
import {
  AlertCircle,
  ArrowLeft,
  Eye,
  EyeOff,
  Loader2,
  LockKeyhole,
  PlugZap,
  ShieldCheck,
  TimerOff,
} from 'lucide-react'
import { useAuth } from '@/auth/AuthProvider'
import { loginRequestSchema } from '@/auth/auth.types'
import { ApiError } from '@/api/client'
import { OverviewBackground } from '@/components/effects/OverviewBackground'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { homeFor } from '@/lib/routes'

function Notice({ tone, icon, children }: { tone: 'warn' | 'error'; icon: React.ReactNode; children: React.ReactNode }) {
  const color =
    tone === 'warn'
      ? 'text-sev-medium border-sev-medium/30 bg-sev-medium/10'
      : 'text-sev-critical border-sev-critical/30 bg-sev-critical/10'
  return (
    <div role="alert" className={`flex items-start gap-2 rounded-lg border px-3 py-2.5 text-sm ${color}`}>
      <span className="mt-0.5 shrink-0">{icon}</span>
      <span>{children}</span>
    </div>
  )
}

// Principles the product actually follows (see BACKEND_INTEGRATION.md) - not metrics or claims about customers.
const ORBIT_LABELS = ['Metadata only', 'No decryption', 'Server-side auth', 'Role-based access']

/** Decorative orbital "trust ring": concentric rings with slowly travelling nodes around a shield. */
function OrbitalRing() {
  const rings = [
    { r: 92, dur: 40, dots: 1, dash: '2 6' },
    { r: 142, dur: 62, dots: 2, dash: '' },
    { r: 192, dur: 90, dots: 1, dash: '1 9' },
  ]
  return (
    <div className="relative mx-auto aspect-square w-full max-w-[460px]" aria-hidden>
      <div className="absolute inset-0 rounded-full bg-[radial-gradient(closest-side,rgba(0,120,212,0.12),transparent)]" />
      <svg viewBox="-220 -220 440 440" className="absolute inset-0 size-full">
        {rings.map((ring, i) => (
          <g key={ring.r}>
            <circle r={ring.r} fill="none" stroke="#0078D4" strokeOpacity={0.18 + (2 - i) * 0.06} strokeDasharray={ring.dash} />
            <motion.g
              animate={{ rotate: i % 2 ? -360 : 360 }}
              transition={{ duration: ring.dur, repeat: Infinity, ease: 'linear' }}
              style={{ originX: '0px', originY: '0px' }}
            >
              {Array.from({ length: ring.dots }).map((_, d) => {
                const a = (d / ring.dots) * Math.PI * 2 + i
                return (
                  <circle
                    key={d}
                    cx={Math.cos(a) * ring.r}
                    cy={Math.sin(a) * ring.r}
                    r={4}
                    fill="#0078D4"
                    
                  />
                )
              })}
            </motion.g>
          </g>
        ))}
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <div className="flex size-24 items-center justify-center rounded-full border border-cyan/40 bg-background/80 text-cyan shadow-[0_0_40px_-8px_var(--accent-cyan)] backdrop-blur">
          <ShieldCheck className="size-10" />
        </div>
      </div>
      {ORBIT_LABELS.map((label, i) => {
        const pos = [
          'left-1/2 top-[2%] -translate-x-1/2',
          'right-0 top-1/2 -translate-y-1/2',
          'bottom-[2%] left-1/2 -translate-x-1/2',
          'left-0 top-1/2 -translate-y-1/2',
        ][i]
        return (
          <span
            key={label}
            className={`absolute ${pos} whitespace-nowrap rounded-full border border-border bg-surface/90 px-3 py-1 text-[11px] font-medium text-muted-foreground backdrop-blur`}
          >
            {label}
          </span>
        )
      })}
    </div>
  )
}

export function LoginPage() {
  const { status, user, login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation() as { state?: { reason?: string } }
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [show, setShow] = useState(false)
  const [busy, setBusy] = useState(false)
  const [fieldErrors, setFieldErrors] = useState<{ username?: string; password?: string }>({})
  const [formError, setFormError] = useState<string | null>(null)

  if (status === 'authenticated' && user) return <Navigate to={homeFor(user.role)} replace />

  const unavailable = status === 'unconfigured' || status === 'unavailable'
  const expired = status === 'expired' || location.state?.reason === 'expired'

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setFormError(null)
    const parsed = loginRequestSchema.safeParse({ username, password })
    if (!parsed.success) {
      const f = parsed.error.flatten().fieldErrors
      setFieldErrors({ username: f.username?.[0], password: f.password?.[0] })
      return
    }
    setFieldErrors({})
    setBusy(true)
    try {
      const u = await login(parsed.data)
      navigate(homeFor(u.role), { replace: true })
    } catch (err) {
      if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
        setFormError('Invalid employee ID or password.')
      } else if (err instanceof ApiError && err.kind === 'not_configured') {
        setFormError('Authentication is unavailable: no backend is configured.')
      } else if (err instanceof ApiError && err.kind === 'network') {
        setFormError('The authentication service could not be reached.')
      } else if (err instanceof ApiError && err.kind === 'invalid_response') {
        setFormError('The authentication service returned an unexpected response.')
      } else {
        setFormError('Sign-in failed. Please try again.')
      }
    } finally {
      setBusy(false)
      setPassword('')
    }
  }

  return (
    <MotionConfig reducedMotion="user">
      <div className="grid min-h-screen bg-background lg:grid-cols-2">
        {/* Form side */}
        <div className="relative flex flex-col px-6 py-8 sm:px-12 lg:px-16">
          <div className="flex items-center justify-between">
            <Link to="/" className="flex items-center gap-2 font-semibold tracking-[0.2em]">
              <ShieldCheck className="size-5 text-cyan" /> VEYLIX
            </Link>
            <Link to="/" className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
              <ArrowLeft className="size-3.5" /> Back to site
            </Link>
          </div>

          <div className="mx-auto flex w-full max-w-md flex-1 flex-col justify-center py-10">
            <h1 className="text-3xl font-semibold tracking-tight">Welcome back</h1>
            <p className="mt-2 text-sm text-muted-foreground">
              Sign in with your corporate account. Employees and security analysts use the same sign-in.
            </p>

            <form onSubmit={submit} noValidate className="mt-8 space-y-5">
              {status === 'unconfigured' && (
                <Notice tone="warn" icon={<PlugZap className="size-4" />}>
                  Authentication unavailable - the backend is not configured. Sign-in will be enabled once it is connected.
                </Notice>
              )}
              {status === 'unavailable' && (
                <Notice tone="error" icon={<PlugZap className="size-4" />}>
                  The authentication service is unreachable. Please try again shortly.
                </Notice>
              )}
              {expired && !unavailable && (
                <Notice tone="warn" icon={<TimerOff className="size-4" />}>
                  Your session has expired. Please sign in again.
                </Notice>
              )}
              {formError && (
                <Notice tone="error" icon={<AlertCircle className="size-4" />}>
                  {formError}
                </Notice>
              )}

              <div>
                <label htmlFor="username" className="mb-2 block text-sm font-medium">
                  Employee ID or username
                </label>
                <Input
                  id="username"
                  autoComplete="username"
                  autoFocus
                  value={username}
                  disabled={busy || unavailable}
                  aria-invalid={!!fieldErrors.username}
                  aria-describedby={fieldErrors.username ? 'username-error' : undefined}
                  onChange={(e) => setUsername(e.target.value)}
                  className="h-12 bg-surface text-base"
                />
                {fieldErrors.username && (
                  <p id="username-error" className="mt-1.5 text-xs text-sev-critical">
                    {fieldErrors.username}
                  </p>
                )}
              </div>

              <div>
                <label htmlFor="password" className="mb-2 block text-sm font-medium">
                  Password
                </label>
                <div className="relative">
                  <Input
                    id="password"
                    type={show ? 'text' : 'password'}
                    autoComplete="current-password"
                    value={password}
                    disabled={busy || unavailable}
                    aria-invalid={!!fieldErrors.password}
                    aria-describedby={fieldErrors.password ? 'password-error' : undefined}
                    onChange={(e) => setPassword(e.target.value)}
                    className="h-12 bg-surface pr-12 text-base"
                  />
                  <button
                    type="button"
                    onClick={() => setShow((s) => !s)}
                    aria-label={show ? 'Hide password' : 'Show password'}
                    className="absolute right-3 top-1/2 -translate-y-1/2 rounded p-1 text-muted-foreground hover:text-foreground"
                  >
                    {show ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                  </button>
                </div>
                {fieldErrors.password && (
                  <p id="password-error" className="mt-1.5 text-xs text-sev-critical">
                    {fieldErrors.password}
                  </p>
                )}
              </div>

              <Button type="submit" size="lg" className="h-12 w-full text-base" disabled={busy || unavailable}>
                {busy ? <Loader2 className="size-4 animate-spin" /> : <LockKeyhole className="size-4" />}
                {busy ? 'Signing in…' : 'Sign in'}
              </Button>
            </form>

            <p className="mt-8 text-xs leading-relaxed text-muted-foreground">
              Credentials are verified by the VEYLIX backend. Passwords are never stored in this browser.
            </p>
          </div>
        </div>

        {/* Brand side */}
        <aside className="relative hidden overflow-hidden border-l border-border lg:flex lg:flex-col lg:items-center lg:justify-center lg:px-12">
          <OverviewBackground height="100%" />
          <div className="relative z-10 w-full max-w-lg">
            <OrbitalRing />
            <div className="mt-10 text-center">
              <p className="text-2xl font-semibold tracking-tight">See the Threat. Never the Data.</p>
              <p className="mx-auto mt-3 max-w-sm text-sm leading-relaxed text-muted-foreground">
                VEYLIX analyzes network behavior - not message or file contents - so investigations never require decrypting traffic.
              </p>
            </div>
          </div>
        </aside>
      </div>
    </MotionConfig>
  )
}
