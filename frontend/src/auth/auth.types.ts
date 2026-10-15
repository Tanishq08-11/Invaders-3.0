import { z } from 'zod'

export const roleSchema = z.preprocess(
  (v) => (typeof v === 'string' ? v.trim().toUpperCase() : v),
  z.enum(['EMPLOYEE', 'SECURITY_ANALYST']),
)
export type Role = z.infer<typeof roleSchema>

/**
 * PROVISIONAL: shape of GET /api/v1/auth/me and GET /api/v1/employees/me.
 * Identity, role and department always come from the backend session.
 */
export const userSchema = z.object({
  id: z.union([z.string(), z.number()]).transform(String),
  username: z.string().nullish(),
  display_name: z.string(),
  role: roleSchema,
  department: z.string().nullish(),
  email: z.string().nullish(),
  storage_used_bytes: z.number().nullish(),
  storage_quota_bytes: z.number().nullish(),
})
export type AuthUser = z.infer<typeof userSchema>

export type AuthStatus =
  | 'unconfigured' // no backend URL configured
  | 'loading' // resolving the session
  | 'authenticated'
  | 'unauthenticated'
  | 'expired' // a previously valid session was rejected
  | 'unavailable' // backend unreachable / bad response

export const loginRequestSchema = z.object({
  username: z.string().trim().min(1, 'Enter your employee ID or username'),
  password: z.string().min(1, 'Enter your password'),
})
export type LoginRequest = z.infer<typeof loginRequestSchema>
