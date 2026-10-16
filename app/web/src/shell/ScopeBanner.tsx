import { useQuery } from '@tanstack/react-query'
import { get } from '../api/client'
import type { ScopeView } from '../api/beacon'
import { useT, type Dict } from '../i18n'
import { Banner } from '../ui/ui'
import '../pages/beacon/beacon.css'

// ScopeBanner: for a user whose traffic is restricted to their Beacon visibility scope
// (docs/integrations.md §3.2), a banner when the scope cannot be loaded (Beacon unreachable:
// traffic pages show nothing) or when Beacon does not know the user.

const strings: Dict = {
  en: {
    'scope.down': 'Beacon is unreachable: your visibility scope cannot be checked, so no traffic is shown.',
    'scope.unknown': 'Beacon does not know your login: no traffic is visible to you. Ask an administrator.',
    'scope.empty': 'Your Beacon visibility scope has no CIs: no traffic is visible to you.',
  },
  ru: {
    'scope.down': 'Beacon недоступен: вашу область видимости не проверить, поэтому трафик не показывается.',
    'scope.unknown': 'Beacon не знает ваш логин: трафик вам не виден. Обратитесь к администратору.',
    'scope.empty': 'В вашей области видимости Beacon нет КЕ: трафик вам не виден.',
  },
}

export function ScopeBanner() {
  const t = useT(strings)
  const q = useQuery({
    queryKey: ['umbrella', 'scope'],
    queryFn: ({ signal }) => get<ScopeView>('/api/umbrella/scope', signal),
    refetchInterval: (query) => (query.state.data?.restricted ? 60_000 : false),
    staleTime: 30_000,
  })
  const s = q.data
  if (!s || !s.restricted) return null
  let title: string | null = null
  if (!s.ok) title = t('scope.down')
  else if (!s.known) title = t('scope.unknown')
  else if (s.mode !== 'all' && s.refs === 0 && s.addresses === 0) title = t('scope.empty')
  if (!title) return null
  return (
    <div className="scope-banner">
      <Banner kind={s.ok ? 'warn' : 'error'} title={title}>
        {!s.ok && s.error}
      </Banner>
    </div>
  )
}
