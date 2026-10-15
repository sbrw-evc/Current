import { useQuery } from '@tanstack/react-query'
import { ExternalLink } from 'lucide-react'
import { get } from '../../api/client'
import { useLocale, useT } from '../../i18n'
import { Page } from '../../shell/Page'
import { useSession } from '../../shell/session'
import { Banner, Card, Chip, formatDate } from '../../ui/ui'
import { spaStrings } from '../spa/strings'

type User = { id: number; username: string; name: string; email: string; source: string; role: string; role_ident: string; disabled: boolean; last_login_at?: string }

// UsersPage: Settings → Users. Read-only records synchronized from SPA; people, their roles and
// their state are managed in SPA ("Managed in SPA").
export default function UsersPage() {
  const t = useT(spaStrings)
  const { locale } = useLocale()
  const { accountURL } = useSession()
  const users = useQuery({ queryKey: ['users'], queryFn: ({ signal }) => get<{ results: User[] }>('/api/users', signal) })
  const spaHome = accountURL ? new URL(accountURL).origin : ''
  return (
    <Page id="users" subtitle={t('us.sub')}>
      <Banner kind="info" title={t('us.managed')}>
        {t('us.managed.text')}{' '}
        {spaHome && (
          <a href={spaHome} target="_blank" rel="noreferrer">
            {t('us.open')} <ExternalLink size={12} />
          </a>
        )}
      </Banner>
      <Card pad={false}>
        <table className="data-table">
          <thead>
            <tr>
              <th>{t('us.col.user')}</th>
              <th>{t('us.col.source')}</th>
              <th>{t('us.col.role')}</th>
              <th>{t('us.col.last')}</th>
              <th>{t('us.col.state')}</th>
            </tr>
          </thead>
          <tbody>
            {users.data?.results.map((u) => (
              <tr key={u.id}>
                <td>
                  <strong>{u.name || u.username}</strong>
                  <div className="hint">
                    {u.username}
                    {u.email && ` · ${u.email}`}
                  </div>
                </td>
                <td>{t(`us.source.${u.source === 'spa' ? 'spa' : 'legacy'}`)}</td>
                <td>
                  {u.role} <code className="muted">{u.role_ident}</code>
                </td>
                <td className="muted">{u.last_login_at ? formatDate(u.last_login_at, locale) : t('us.never')}</td>
                <td>
                  <Chip tone={u.disabled ? 'off' : 'ok'}>{u.disabled ? t('us.disabled') : t('us.active')}</Chip>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </Page>
  )
}
