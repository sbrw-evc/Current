import { lazy, Suspense, type ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { createBrowserRouter, Navigate, Outlet, RouterProvider, useLocation } from 'react-router-dom'
import { useSetupState } from './api/queries'
import { ApiError } from './api/client'
import { LocaleProvider, savedLocale } from './i18n'
import { Guard } from './shell/Page'
import { Shell } from './shell/Shell'
import { savedTheme, systemTheme, ThemeProvider } from './theme'
import { Loading } from './ui/ui'
import { Toaster } from './ui/notify'
import { LoginPage } from './pages/Login'
import { HomePage } from './pages/Home'
import { GoIncident } from './pages/GoIncident'
import { NotFound } from './pages/NotFound'

const SetupPage = lazy(() => import('./pages/Setup'))
const VisualizePage = lazy(() => import('./pages/visualize/VisualizePage'))
const FlowsPage = lazy(() => import('./pages/Flows'))
const ExportersPage = lazy(() => import('./pages/Exporters'))
const InventoryPage = lazy(() => import('./pages/InventoryDB'))
const ClassifiersPage = lazy(() => import('./pages/Classifiers'))
const OpenBaoPage = lazy(() => import('./pages/OpenBao'))

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: (n, e) => !(e instanceof ApiError && e.status >= 400 && e.status < 500) && n < 2,
    },
  },
})

const lazyPage = (node: ReactNode) => <Suspense fallback={<main className="page"><Loading /></main>}>{node}</Suspense>

// SetupGate: while the first-run setup is required, every route leads to the wizard; after it,
// the wizard is gone.
function SetupGate() {
  const { pathname } = useLocation()
  const q = useSetupState()
  if (q.isPending) return null
  const required = q.data?.required === true
  // After the setup every /api/setup* answers 404.
  const finished = (q.data && !required) || (q.error instanceof ApiError && q.error.status === 404)
  if (required && pathname !== '/setup') return <Navigate to="/setup" replace />
  if (finished && pathname === '/setup') return <Navigate to="/login" replace />
  return <Outlet />
}

const router = createBrowserRouter([
  {
    element: <SetupGate />,
    children: [
  { path: '/login', element: <LoginPage /> },
  { path: '/setup', element: lazyPage(<SetupPage />) },
  {
    path: '/',
    element: <Shell />,
    children: [
      { index: true, element: <HomePage /> },
      { path: 'visualize', element: <Guard perm="visualize:view">{lazyPage(<VisualizePage />)}</Guard> },
      { path: 'flows', element: <Guard perm="flows:view">{lazyPage(<FlowsPage />)}</Guard> },
      { path: 'exporters', element: <Guard perm="exporters:view">{lazyPage(<ExportersPage />)}</Guard> },
      { path: 'settings/inventory-db', element: <Guard perm="settings.inventory:view">{lazyPage(<InventoryPage />)}</Guard> },
      { path: 'settings/classifiers', element: <Guard perm="settings.classifiers:view">{lazyPage(<ClassifiersPage />)}</Guard> },
      { path: 'go/incident', element: <GoIncident /> },
      { path: 'settings/openbao', element: <Guard perm="settings.openbao:view">{lazyPage(<OpenBaoPage />)}</Guard> },
      { path: '*', element: <NotFound /> },
    ],
  },
    ],
  },
])

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <LocaleProvider initial={savedLocale() ?? 'ru'}>
        <ThemeProvider initial={savedTheme() ?? systemTheme()}>
          <RouterProvider router={router} />
          <Toaster />
        </ThemeProvider>
      </LocaleProvider>
    </QueryClientProvider>
  )
}
