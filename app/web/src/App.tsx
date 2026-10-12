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
const DetectorRulesPage = lazy(() => import('./pages/detector/RulesPage'))
const DetectorRulePage = lazy(() => import('./pages/detector/RuleEditPage'))
const DetectorStatusPage = lazy(() => import('./pages/detector/StatusPage'))
const InventoryPage = lazy(() => import('./pages/InventoryDB'))
const ClassifiersPage = lazy(() => import('./pages/Classifiers'))
const OpenBaoPage = lazy(() => import('./pages/OpenBao'))
const ApiTokensPage = lazy(() => import('./pages/settings/ApiTokens'))
const EntraPage = lazy(() => import('./pages/settings/Entra'))
const ThreatPage = lazy(() => import('./pages/settings/Threat'))
const SnmpPage = lazy(() => import('./pages/settings/Snmp'))
const BmpPage = lazy(() => import('./pages/settings/Bmp'))
const UmbrellaSettingsPage = lazy(() => import('./pages/umbrella/UmbrellaSettings'))
const DependenciesPage = lazy(() => import('./pages/umbrella/Dependencies'))

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
      { path: 'detector', element: <Navigate to="/detector/status" replace /> },
      { path: 'detector/rules', element: <Guard perm="detector:view">{lazyPage(<DetectorRulesPage />)}</Guard> },
      { path: 'detector/rules/:id', element: <Guard perm="detector:view">{lazyPage(<DetectorRulePage />)}</Guard> },
      { path: 'detector/status', element: <Guard perm="detector:view">{lazyPage(<DetectorStatusPage />)}</Guard> },
      { path: 'settings/inventory-db', element: <Guard perm="settings.inventory:view">{lazyPage(<InventoryPage />)}</Guard> },
      { path: 'settings/classifiers', element: <Guard perm="settings.classifiers:view">{lazyPage(<ClassifiersPage />)}</Guard> },
      { path: 'go/incident', element: <GoIncident /> },
      { path: 'settings/openbao', element: <Guard perm="settings.openbao:view">{lazyPage(<OpenBaoPage />)}</Guard> },
      { path: 'settings/api-tokens', element: <Guard perm="tokens:view">{lazyPage(<ApiTokensPage />)}</Guard> },
      { path: 'settings/entra', element: <Guard perm="users:view">{lazyPage(<EntraPage />)}</Guard> },
      { path: 'settings/threat', element: <Guard perm="settings.threat:view">{lazyPage(<ThreatPage />)}</Guard> },
      { path: 'settings/snmp', element: <Guard perm="settings.snmp:view">{lazyPage(<SnmpPage />)}</Guard> },
      { path: 'settings/bmp', element: <Guard perm="settings.bmp:view">{lazyPage(<BmpPage />)}</Guard> },
      { path: 'settings/umbrella', element: <Guard perm="settings.umbrella:view">{lazyPage(<UmbrellaSettingsPage />)}</Guard> },
      { path: 'dependencies', element: <Guard perm="dependencies:view">{lazyPage(<DependenciesPage />)}</Guard> },
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
