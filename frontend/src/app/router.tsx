import { createBrowserRouter, Navigate } from 'react-router-dom'
import { SocShell } from '@/components/layout/SocShell'
import { EmployeeShell } from '@/components/layout/EmployeeShell'
import { RequireRole } from '@/auth/guards'
import { useAuth } from '@/auth/AuthProvider'
import { homeFor, routes } from '@/lib/routes'
import LandingPage from '@/features/landing/LandingPage'
import { StateBlock } from '@/components/common/States'

// Public landing page; signed-in users go straight to their workspace.
function Root() {
  const { user } = useAuth()
  return user ? <Navigate to={homeFor(user.role)} replace /> : <LandingPage />
}


export const router = createBrowserRouter([
  { path: '/', element: <Root /> },
  { path: routes.login, lazy: () => import('@/features/auth/LoginPage').then((m) => ({ Component: m.LoginPage })) },
  {
    element: <RequireRole role="SECURITY_ANALYST" />,
    children: [
      {
        element: <SocShell />,
        children: [
          { path: routes.soc.overview, lazy: () => import('@/features/soc/OverviewPage').then((m) => ({ Component: m.SocOverviewPage })) },
          { path: routes.soc.alerts, lazy: () => import('@/features/soc/AlertCenterPage').then((m) => ({ Component: m.AlertCenterPage })) },
          { path: '/soc/alerts/:alertId', lazy: () => import('@/features/soc/IncidentPage').then((m) => ({ Component: m.IncidentPage })) },
          { path: '/soc/devices/:deviceId', lazy: () => import('@/features/soc/DevicePage').then((m) => ({ Component: m.DevicePage })) },
        ],
      },
    ],
  },
  {
    element: <RequireRole role="EMPLOYEE" />,
    children: [
      {
        element: <EmployeeShell />,
        children: [
          { path: routes.employee.dashboard, lazy: () => import('@/features/employee/DashboardPage').then((m) => ({ Component: m.EmployeeDashboardPage })) },
          { path: routes.employee.files, lazy: () => import('@/features/employee/FilesPage').then((m) => ({ Component: m.FilesPage })) },
          { path: routes.employee.upload, lazy: () => import('@/features/employee/UploadPage').then((m) => ({ Component: m.UploadPage })) },
          { path: routes.employee.activity, lazy: () => import('@/features/employee/ActivityPage').then((m) => ({ Component: m.ActivityPage })) },
          { path: routes.employee.profile, lazy: () => import('@/features/employee/DashboardAndProfile').then((m) => ({ Component: m.ProfilePage })) },
        ],
      },
    ],
  },
  {
    path: '*',
    element: (
      <div className="flex min-h-screen items-center justify-center">
        <StateBlock title="Page not found" description="This page does not exist." />
      </div>
    ),
  },
])
