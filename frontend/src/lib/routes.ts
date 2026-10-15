const enc = encodeURIComponent

export const routes = {
  login: '/login',
  soc: {
    overview: '/soc',
    alerts: '/soc/alerts',
    events: '/soc/events',
    collector: '/soc/collector',
    alert: (id: string) => `/soc/alerts/${enc(id)}`,
    device: (id: string) => `/soc/devices/${enc(id)}`,
  },
  employee: {
    dashboard: '/employee/dashboard',
    files: '/employee/files',
    upload: '/employee/files/upload',
    activity: '/employee/activity',
    profile: '/employee/profile',
  },
} as const

/** Default landing route for an authenticated role. */
export const homeFor = (role: 'EMPLOYEE' | 'SECURITY_ANALYST' | 'ADMIN') =>
  role === 'EMPLOYEE' ? routes.employee.dashboard : routes.soc.overview
