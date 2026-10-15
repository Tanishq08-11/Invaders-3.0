import { z } from 'zod'
import { request } from '@/api/client'
import { userSchema, type AuthUser, type LoginRequest } from './auth.types'

/**
 * PROVISIONAL auth contract (proposed, not yet confirmed by Person 4):
 *   POST /api/v1/auth/login   { username, password } -> sets an HttpOnly session cookie, returns the user
 *   GET  /api/v1/auth/me      -> current user (401 when there is no valid session)
 *   POST /api/v1/auth/logout  -> clears the session
 * Credentials are never checked, cached or stored in the frontend.
 */
const loginResponse = userSchema.or(z.object({ user: userSchema }).transform((r) => r.user))

export const authService = {
  login: (body: LoginRequest): Promise<AuthUser> =>
    request('/api/v1/auth/login', { method: 'POST', body, schema: loginResponse }),
  me: (signal?: AbortSignal): Promise<AuthUser> => request('/api/v1/auth/me', { schema: userSchema, signal }),
  logout: (): Promise<unknown> => request('/api/v1/auth/logout', { method: 'POST', body: {}, schema: z.unknown() }),
}
