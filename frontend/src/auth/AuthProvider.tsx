import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { ApiError, isApiConfigured, UNAUTHORIZED_EVENT } from '@/api/client'
import { authService } from './auth.service'
import type { AuthStatus, AuthUser, LoginRequest } from './auth.types'

interface AuthContextValue {
  status: AuthStatus
  user: AuthUser | null
  login: (body: LoginRequest) => Promise<AuthUser>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const qc = useQueryClient()
  const [status, setStatus] = useState<AuthStatus>(isApiConfigured ? 'loading' : 'unconfigured')
  const [user, setUser] = useState<AuthUser | null>(null)

  // Resolve any existing backend session on load.
  useEffect(() => {
    if (!isApiConfigured) return
    const ctrl = new AbortController()
    authService
      .me(ctrl.signal)
      .then((u) => {
        setUser(u)
        setStatus('authenticated')
      })
      .catch((e: unknown) => {
        if (e instanceof DOMException && e.name === 'AbortError') return
        setUser(null)
        setStatus(e instanceof ApiError && e.status === 401 ? 'unauthenticated' : 'unavailable')
      })
    return () => ctrl.abort()
  }, [])

  // Any request rejected with 401 while signed in means the session ended.
  useEffect(() => {
    const onUnauthorized = () => {
      setStatus((s) => (s === 'authenticated' ? 'expired' : s))
      setUser((u) => (u ? null : u))
      qc.clear()
    }
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
  }, [qc])

  const login = useCallback(async (body: LoginRequest) => {
    const u = await authService.login(body)
    setUser(u)
    setStatus('authenticated')
    return u
  }, [])

  const logout = useCallback(async () => {
    try {
      await authService.logout()
    } finally {
      setUser(null)
      setStatus('unauthenticated')
      qc.clear()
    }
  }, [qc])

  const value = useMemo(() => ({ status, user, login, logout }), [status, user, login, logout])
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}
