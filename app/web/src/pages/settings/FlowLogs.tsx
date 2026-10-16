import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Cloud, Copy, KeyRound, Save, Trash2 } from 'lucide-react'
import { get, put } from '../../api/client'
import { errorText, useT, type Dict } from '../../i18n'
import { Page } from '../../shell/Page'
import { useSession } from '../../shell/session'
import { notify } from '../../ui/notify'
import { Banner, Button, Card, Chip, Field, Loading, Password, Switch } from '../../ui/ui'
import { ingestURL, MIN_TOKEN, problem, providerBody, PROVIDERS, randomToken, snippet, type FlowLogsView, type Provider, type ProviderDraft } from './FlowLogsModel'

// Settings → Cloud flow logs (docs/api.md, "Cloud flow logs"): AWS VPC / Firehose, Azure NSG / VNet
// and GCP Pub/Sub push endpoints. Tokens are write-only (OpenBao); the page shows each ingest URL and
// the cloud-side setup.

const strings: Dict = {
  en: {
    'fl.sub': 'Cloud flow logs posted to Current and processed like NetFlow / IPFIX / sFlow',
    'fl.aws': 'AWS VPC Flow Logs',
    'fl.azure': 'Azure NSG / VNet flow logs',
    'fl.gcp': 'GCP VPC Flow Logs',
    'fl.aws.how': 'Kinesis Data Firehose HTTP endpoint delivery: the token is the Firehose access key (X-Amz-Firehose-Access-Key). CloudWatch Logs JSON and plain log lines are accepted too (Authorization: Bearer).',
    'fl.azure.how': 'Azure writes flow logs to a storage account; an Azure Function (Event Grid BlobCreated) posts each blob to Current with Authorization: Bearer.',
    'fl.gcp.how': 'A Log Router sink to a Pub/Sub topic with a push subscription to Current; Pub/Sub push cannot send headers, so the token is the ?token= parameter. GCP reports estimated totals: no sampling scaling is applied.',
    'fl.enabled': 'Accept flow logs',
    'fl.token': 'Ingest token',
    'fl.token.set': 'Stored in OpenBao',
    'fl.token.unset': 'Not set',
    'fl.token.hint': 'At least {n} characters; write-only. Leave empty to keep the stored token.',
    'fl.generate': 'Generate',
    'fl.remove': 'Remove the token',
    'fl.url': 'Ingest URL',
    'fl.url.local': 'From this browser\'s address: set the public URL under the general settings for the address the cloud reaches.',
    'fl.copy': 'Copy',
    'fl.copied': 'Copied',
    'fl.setup': 'Setup',
    'fl.save': 'Save',
    'fl.saved': 'Cloud flow log settings saved',
    'fl.unavailable': 'This process has no pipeline bus: flow logs are refused (501). Run Current in role all, or give the api role a NATS address.',
    'fl.err.token': 'A token is required to accept flow logs',
    'fl.err.short': 'The token must have at least 16 characters',
    'fl.on': 'On',
    'fl.off': 'Off',
  },
  ru: {
    'fl.sub': 'Облачные журналы потоков, которые отправляются в Current и обрабатываются как NetFlow / IPFIX / sFlow',
    'fl.aws': 'AWS VPC Flow Logs',
    'fl.azure': 'Журналы потоков Azure NSG / VNet',
    'fl.gcp': 'GCP VPC Flow Logs',
    'fl.aws.how': 'Доставка Kinesis Data Firehose на HTTP endpoint: токен — ключ доступа Firehose (X-Amz-Firehose-Access-Key). Также принимаются JSON CloudWatch Logs и строки журнала (Authorization: Bearer).',
    'fl.azure.how': 'Azure пишет журналы потоков в storage account; Azure Function (Event Grid BlobCreated) отправляет каждый blob в Current с Authorization: Bearer.',
    'fl.gcp.how': 'Sink Log Router в тему Pub/Sub с push-подпиской на Current; push Pub/Sub не умеет передавать заголовки, поэтому токен — параметр ?token=. GCP передаёт оценённые итоги: масштабирование по семплированию не применяется.',
    'fl.enabled': 'Принимать журналы потоков',
    'fl.token': 'Токен приёма',
    'fl.token.set': 'Хранится в OpenBao',
    'fl.token.unset': 'Не задан',
    'fl.token.hint': 'Не короче {n} символов; только запись. Оставьте пустым, чтобы сохранить текущий.',
    'fl.generate': 'Создать',
    'fl.remove': 'Удалить токен',
    'fl.url': 'Адрес приёма',
    'fl.url.local': 'По адресу этого браузера: задайте публичный адрес в общих настройках — тот, что доступен из облака.',
    'fl.copy': 'Копировать',
    'fl.copied': 'Скопировано',
    'fl.setup': 'Настройка',
    'fl.save': 'Сохранить',
    'fl.saved': 'Настройки облачных журналов сохранены',
    'fl.unavailable': 'У этого процесса нет шины конвейера: журналы отклоняются (501). Запустите Current в роли all или укажите адрес NATS для роли api.',
    'fl.err.token': 'Чтобы принимать журналы, нужен токен',
    'fl.err.short': 'Токен должен быть не короче 16 символов',
    'fl.on': 'Включено',
    'fl.off': 'Выключено',
  },
}

const empty = (enabled: boolean): ProviderDraft => ({ enabled, token: '', remove: false })

export default function FlowLogsPage() {
  const t = useT(strings)
  const q = useQuery({ queryKey: ['flowlogs'], queryFn: ({ signal }) => get<FlowLogsView>('/api/settings/flowlogs', signal) })
  return (
    <Page id="flowlogs" subtitle={t('fl.sub')}>
      {q.error && <Banner kind="error" title={errorText(t, q.error).message} />}
      {q.data && !q.data.available && <Banner kind="warn" title={t('fl.unavailable')} />}
      {q.isPending ? <Loading /> : q.data ? <FlowLogsForm view={q.data} key={JSON.stringify(q.data)} /> : null}
    </Page>
  )
}

function FlowLogsForm({ view }: { view: FlowLogsView }) {
  const t = useT(strings)
  const { can } = useSession()
  const qc = useQueryClient()
  const editable = can('settings.flowlogs:edit')
  const [drafts, setDrafts] = useState<Record<Provider, ProviderDraft>>({ aws: empty(view.aws.enabled), azure: empty(view.azure.enabled), gcp: empty(view.gcp.enabled) })
  const set = (p: Provider, d: Partial<ProviderDraft>) => setDrafts({ ...drafts, [p]: { ...drafts[p], ...d } })
  const problems = PROVIDERS.map((p) => problem(view[p], drafts[p])).filter((x): x is string => !!x)
  const save = useMutation({
    mutationFn: () => put<FlowLogsView>('/api/settings/flowlogs', Object.fromEntries(PROVIDERS.map((p) => [p, providerBody(drafts[p])]))),
    onSuccess: (v) => {
      qc.setQueryData(['flowlogs'], v)
      notify('ok', t('fl.saved'))
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })
  const copy = (text: string) => void navigator.clipboard?.writeText(text).then(() => notify('ok', t('fl.copied')))
  return (
    <div className="stack">
      {PROVIDERS.map((p) => {
        const v = view[p]
        const d = drafts[p]
        const url = ingestURL(v, window.location.origin)
        return (
          <Card key={p} title={t(`fl.${p}`)} actions={<Chip tone={v.enabled ? 'ok' : 'off'}>{t(v.enabled ? 'fl.on' : 'fl.off')}</Chip>}>
            <p className="muted">{t(`fl.${p}.how`)}</p>
            <Switch checked={d.enabled && !d.remove} onChange={(x) => set(p, { enabled: x, remove: false })} label={t('fl.enabled')} disabled={!editable} />
            <Field label={t('fl.token')} hint={t('fl.token.hint', { n: MIN_TOKEN })}>
              {(id) => (
                <div className="row">
                  <Chip tone={v.token_set && !d.remove ? 'ok' : 'off'} dot>
                    <KeyRound size={12} /> {t(v.token_set && !d.remove ? 'fl.token.set' : 'fl.token.unset')}
                  </Chip>
                  {editable && (
                    <>
                      <Password id={id} value={d.token} autoComplete="new-password" onChange={(e) => set(p, { token: e.target.value.trim(), remove: false })} />
                      <Button size="sm" onClick={() => set(p, { token: randomToken(), remove: false })}>
                        {t('fl.generate')}
                      </Button>
                      {d.token && (
                        <Button size="sm" variant="ghost" aria-label={t('fl.copy')} title={t('fl.copy')} onClick={() => copy(d.token)}>
                          <Copy size={14} />
                        </Button>
                      )}
                      {v.token_set && (
                        <Button size="sm" variant="ghost" aria-label={t('fl.remove')} title={t('fl.remove')} onClick={() => set(p, { token: '', remove: true, enabled: false })}>
                          <Trash2 size={14} />
                        </Button>
                      )}
                    </>
                  )}
                </div>
              )}
            </Field>
            <Field label={t('fl.url')} hint={v.url ? undefined : t('fl.url.local')}>
              {() => (
                <div className="row">
                  <code style={{ wordBreak: 'break-all' }}>{url}</code>
                  <Button size="sm" variant="ghost" aria-label={t('fl.copy')} title={t('fl.copy')} onClick={() => copy(url)}>
                    <Copy size={14} />
                  </Button>
                </div>
              )}
            </Field>
            <h3>
              <Cloud size={15} /> {t('fl.setup')}
            </h3>
            <pre className="code-block">{snippet(p, url)}</pre>
          </Card>
        )
      })}
      {problems.map((k) => (
        <Banner key={k} kind="warn" title={t(k)} />
      ))}
      {editable && (
        <div className="card-actions">
          <Button variant="primary" busy={save.isPending} disabled={problems.length > 0} onClick={() => save.mutate()}>
            {!save.isPending && <Save size={15} />}
            {t('fl.save')}
          </Button>
        </div>
      )}
    </div>
  )
}
