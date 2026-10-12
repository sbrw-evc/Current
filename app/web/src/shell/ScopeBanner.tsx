import { useQuery } from '@tanstack/react-query'
import { get } from '../api/client'
import type { ScopeView } from '../api/umbrella'
import { useT, type Dict } from '../i18n'
import { Banner } from '../ui/ui'
import '../pages/umbrella/umbrella.css'

// ScopeBanner: for a user whose traffic is restricted to their Umbrella visibility scope
// (docs/integrations.md §3.2), a banner when the scope cannot be loaded (Umbrella unreachable:
// traffic pages show nothing) or when Umbrella does not know the user.

const strings: Dict = {
  en: {
    'scope.down': 'Umbrella is unreachable: your visibility scope cannot be checked, so no traffic is shown.',
    'scope.unknown': 'Umbrella does not know your login: no traffic is visible to you. Ask an administrator.',
    'scope.empty': 'Your Umbrella visibility scope has no CIs: no traffic is visible to you.',
  },
  ru: {
    'scope.down': 'Umbrella недоступна: вашу область видимости не проверить, поэтому трафик не показывается.',
    'scope.unknown': 'Umbrella не знает ваш логин: трафик вам не виден. Обратитесь к администратору.',
    'scope.empty': 'В вашей области видимости Umbrella нет КЕ: трафик вам не виден.',
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
