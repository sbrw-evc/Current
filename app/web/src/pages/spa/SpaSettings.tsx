import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ExternalLink, RefreshCw } from 'lucide-react'
import { get, post } from '../../api/client'
import { errorText, useLocale, useT } from '../../i18n'
import { Page } from '../../shell/Page'
import { useSession } from '../../shell/session'
import { notify } from '../../ui/notify'
import { Banner, Button, Card, Chip, formatDate, Loading, Rows } from '../../ui/ui'
import { SPA_PROTOCOL, type SpaView } from './model'
import { spaStrings } from './strings'

// Settings → SPA: the connection to the Single Point of Authorization, the last synchronization of
// people, and the role catalogue Flow publishes to SPA.
export default function SpaSettingsPage() {
  const t = useT(spaStrings)
  const { locale } = useLocale()
  const qc = useQueryClient()
  const { can } = useSession()
  const q = useQuery({ queryKey: ['spa'], queryFn: ({ signal }) => get<SpaView>('/api/settings/spa', signal) })
  const sync = useMutation({
    mutationFn: () => post<SpaView>('/api/settings/spa/sync'),
    onSuccess: (v) => {
      qc.setQueryData(['spa'], v)
      void qc.invalidateQueries({ queryKey: ['users'] })
      if (v.ok) notify('ok', t('spa.sync.done'))
      else notify('error', t('spa.sync.failed'), v.error)
    },
    onError: (e) => {
      const x = errorText(t, e)
      notify('error', x.message, x.detail)
    },
  })
  const v = q.data
  const interval = v?.interval === '5m0s' ? (locale === 'ru' ? '5 минут' : '5 minutes') : (v?.interval ?? '')
  return (
    <Page
      id="spa"
      subtitle={t('spa.sub', { interval })}
      actions={
        can('users:edit') &&
        v?.connected && (
          <Button variant="primary" busy={sync.isPending} onClick={() => sync.mutate()}>
            <RefreshCw size={16} /> {t('spa.sync.now')}
          </Button>
        )
      }
    >
      {q.isPending && <Loading />}
      {v && !v.connected && (
        <Banner kind="warn" title={t('notconnected.title')}>
          {v.key_error && <p>{v.key_error}</p>}
          <ol className="spa-steps">
            <li>{t('notconnected.step1', { redirect: v.redirect_uri })}</li>
            <li>{t('notconnected.step2')}</li>
            <li>{t('notconnected.step3')}</li>
          </ol>
          <a href={SPA_PROTOCOL} target="_blank" rel="noreferrer">
            {t('notconnected.docs')}
          </a>
        </Banner>
      )}
      {v && (
        <div className="cards">
          <Card title={t('spa.connection')}>
            <Rows
              rows={[
                [t('spa.issuer'), v.issuer],
                [t('spa.application'), v.application?.name ? `${v.application.name} (${v.application.type})` : ''],
                [t('spa.client'), v.client_id],
                [t('spa.key'), v.key_source ? t(`spa.key.${v.key_source}`) : ''],
                [t('spa.redirect'), <code key="r">{v.redirect_uri}</code>],
                [t('spa.postlogout'), <code key="p">{v.post_logout_redirect_uri}</code>],
                [t('spa.methods'), v.methods.map((m) => m.title).join(', ')],
                [
                  t('spa.account'),
                  v.account_url && (
                    <a key="a" href={v.account_url} target="_blank" rel="noreferrer">
                      {v.account_url} <ExternalLink size={12} />
                    </a>
                  ),
                ],
              ]}
            />
          </Card>
          <Card title={t('spa.sync')}>
            <Rows
              rows={[
                [
                  t('spa.sync.last'),
                  v.last_sync ? (
                    <span key="s" className="row">
                      {formatDate(v.last_sync, locale)} <Chip tone={v.ok ? 'ok' : 'error'}>{v.ok ? t('spa.sync.ok') : t('spa.sync.failed')}</Chip>
                    </span>
                  ) : (
                    t('spa.sync.never')
                  ),
                ],
                [t('spa.sync'), v.last_sync ? t('spa.sync.changes', { created: v.created, bound: v.bound, updated: v.updated, disabled: v.disabled }) : ''],
                [t('spa.users.enabled'), v.counts.enabled],
                [t('spa.users.disabled'), v.counts.disabled],
                [t('spa.users.legacy'), v.counts.legacy],
              ]}
            />
            {v.error && <Banner kind="error" title={v.error} />}
            {v.conflicts.length > 0 && <Banner kind="warn" title={t('spa.conflicts', { names: v.conflicts.join(', ') })} />}
            {v.no_role.length > 0 && <Banner kind="warn" title={t('spa.norole', { names: v.no_role.join(', ') })} />}
          </Card>
        </div>
      )}
      {v && (
        <Card title={t('spa.catalogue')} pad={false}>
          <p className="muted card-pad">
            {t('spa.catalogue.text')}{' '}
            {v.catalogue.error
              ? t('spa.catalogue.error', { error: v.catalogue.error })
              : v.catalogue.at
                ? t('spa.catalogue.at', { when: formatDate(v.catalogue.at, locale) })
                : t('spa.catalogue.never')}
          </p>
          <table className="data-table">
            <thead>
              <tr>
                <th>{t('spa.col.id')}</th>
                <th>{t('spa.col.name')}</th>
                <th>{t('spa.col.description')}</th>
              </tr>
            </thead>
            <tbody>
              {v.roles.map((r) => (
                <tr key={r.id}>
                  <td>
                    <code>{r.id}</code>
                  </td>
                  <td>{r.name}</td>
                  <td className="muted">{r.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </Page>
  )
}
