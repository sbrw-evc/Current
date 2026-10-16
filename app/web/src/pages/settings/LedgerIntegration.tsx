import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Copy, ExternalLink, Plus } from 'lucide-react'
import { get, post, put } from '../../api/client'
import { errorText, useT, type Dict } from '../../i18n'
import { notify } from '../../ui/notify'
import { Button, Card } from '../../ui/ui'
import { SecretField } from '../../ui/SecretField'
import { deviceCreateUrl, type InventoryIntegration, type InventoryIntegrationUpdate } from './LedgerModel'

// Settings → Ledger: the Current side of the Ledger integration (docs/integrations.md §2) —
// the change-notification hook (URL + shared secret) and the optional editor token behind
// "Create in Ledger" in the Unknown lists. Secrets are write-only and kept in OpenBao.

const strings: Dict = {
  en: {
    'invi.title': 'Integration with Ledger',
    'invi.text':
      'In Ledger, add an integration of kind "flow" with this Current address and an API token of a role with integrations.inventory:read. Its change notifications trigger an early synchronization.',
    'invi.hook': 'Hook address',
    'invi.copy': 'Copy',
    'invi.copied': 'Address copied',
    'invi.secret': 'Hook secret',
    'invi.secret.hint': 'The secret Ledger shows once when the flow integration is created; requests are signed with it.',
    'invi.write': 'Editor token (optional)',
    'invi.write.hint': 'A token of a Ledger editor: enables "Create in Ledger" in the lists of unknown addresses.',
    'invi.remove': 'Remove',
    'invi.saved': 'Integration settings saved',
    'invi.removed': 'Removed',
    'invi.nourl': 'Set Current’s address under Settings → General to get an absolute hook address.',
    'unk.create': 'Create in Ledger',
    'unk.created': '{address} created in Ledger',
    'unk.createDevice': 'Create device',
  },
  ru: {
    'invi.title': 'Интеграция с Ledger',
    'invi.text':
      'В Ledger добавьте интеграцию типа «flow» с адресом Current и API-токеном роли с правом integrations.inventory:read. Её уведомления об изменениях запускают досрочную синхронизацию.',
    'invi.hook': 'Адрес вебхука',
    'invi.copy': 'Скопировать',
    'invi.copied': 'Адрес скопирован',
    'invi.secret': 'Секрет вебхука',
    'invi.secret.hint': 'Секрет, который Ledger показывает один раз при создании интеграции flow; им подписываются запросы.',
    'invi.write': 'Токен редактора (необязательно)',
    'invi.write.hint': 'Токен редактора Ledger: включает «Создать в Ledger» в списках неизвестных адресов.',
    'invi.remove': 'Удалить',
    'invi.saved': 'Настройки интеграции сохранены',
    'invi.removed': 'Удалено',
    'invi.nourl': 'Задайте адрес Current в «Настройки → Общие», чтобы получить полный адрес вебхука.',
    'unk.create': 'Создать в Ledger',
    'unk.created': '{address} создан в Ledger',
    'unk.createDevice': 'Создать устройство',
  },
}

const KEY = ['inventory-db', 'integration']

export function useInventoryIntegration(enabled = true) {
  return useQuery({ queryKey: KEY, queryFn: ({ signal }) => get<InventoryIntegration>('/api/inventory-db/integration', signal), retry: false, enabled })
}

export function LedgerIntegrationCard({ canEdit }: { canEdit: boolean }) {
  const t = useT(strings)
  const qc = useQueryClient()
  const q = useInventoryIntegration()
  const [secret, setSecret] = useState('')
  const [token, setToken] = useState('')
  const save = useMutation({
    mutationFn: (body: InventoryIntegrationUpdate) => put<InventoryIntegration>('/api/inventory-db/integration', body),
    onSuccess: (v, body) => {
      qc.setQueryData(KEY, v)
      setSecret('')
      setToken('')
      const removed = body.hook_secret === '' || body.write_token === ''
      notify('ok', t(removed ? 'invi.removed' : 'invi.saved'))
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })
  if (!q.data) return null
  const v = q.data
  const absolute = /^https?:\/\//i.test(v.hook_url)
  return (
    <Card title={t('invi.title')} className="inventory-integration">
      <p className="muted">{t('invi.text')}</p>
      <div className="field">
        <label>{t('invi.hook')}</label>
        <div className="row inventory-hook-url">
          <code style={{ wordBreak: 'break-all' }}>{v.hook_url}</code>
          <Button
            size="sm"
            variant="ghost"
            aria-label={t('invi.copy')}
            title={t('invi.copy')}
            onClick={() => void navigator.clipboard?.writeText(v.hook_url).then(() => notify('ok', t('invi.copied')))}
          >
            <Copy size={14} />
          </Button>
        </div>
        {!absolute && <div className="hint">{t('invi.nourl')}</div>}
      </div>
      <form
        className="stack"
        onSubmit={(e) => {
          e.preventDefault()
          const body: InventoryIntegrationUpdate = {}
          if (secret) body.hook_secret = secret
          if (token) body.write_token = token
          save.mutate(body)
        }}
        noValidate
      >
        <fieldset className="plain-fieldset stack" disabled={!canEdit}>
          <SecretField label={t('invi.secret')} value={secret} onChange={setSecret} isSet={v.hook_secret_set} hint={t('invi.secret.hint')} />
          <SecretField label={t('invi.write')} value={token} onChange={setToken} isSet={v.write_token_set} hint={t('invi.write.hint')} />
        </fieldset>
        {canEdit && (
          <div className="card-actions row">
            {v.hook_secret_set && (
              <Button variant="ghost" size="sm" disabled={save.isPending} onClick={() => save.mutate({ hook_secret: '' })}>
                {t('invi.remove')}: {t('invi.secret').toLowerCase()}
              </Button>
            )}
            {v.write_token_set && (
              <Button variant="ghost" size="sm" disabled={save.isPending} onClick={() => save.mutate({ write_token: '' })}>
                {t('invi.remove')}: {t('invi.write').replace(/\s*\(.*\)$/, '').toLowerCase()}
              </Button>
            )}
            <Button type="submit" variant="primary" busy={save.isPending} disabled={!secret && !token}>
              {t('save')}
            </Button>
          </div>
        )}
      </form>
    </Card>
  )
}

// CreateAddressButton: "Create in Ledger" for an unknown address (shown only with an editor token).
export function CreateAddressButton({ address, onCreated }: { address: string; onCreated?: () => void }) {
  const t = useT(strings)
  const qc = useQueryClient()
  const [done, setDone] = useState(false)
  const create = useMutation({
    mutationFn: () => post<{ ok: boolean; address: string }>('/api/inventory-db/unknown/create', { address }),
    onSuccess: () => {
      setDone(true)
      notify('ok', t('unk.created', { address }))
      void qc.invalidateQueries({ queryKey: ['inventory-db', 'unknown'] })
      onCreated?.()
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })
  if (done) return null
  return (
    <Button size="sm" variant="ghost" busy={create.isPending} onClick={() => create.mutate()} title={t('unk.create')} aria-label={`${t('unk.create')}: ${address}`}>
      {!create.isPending && <Plus size={14} />}
      {t('unk.create')}
    </Button>
  )
}

// CreateDeviceLink: opens Ledger's device creation form for an unknown exporter.
export function CreateDeviceLink({ inventoryUrl, address }: { inventoryUrl: string; address: string }) {
  const t = useT(strings)
  const href = deviceCreateUrl(inventoryUrl)
  if (!href) return null
  return (
    <a className="btn btn-ghost btn-sm" href={href} target="_blank" rel="noopener noreferrer" title={`${t('unk.createDevice')}: ${address}`}>
      <ExternalLink size={14} /> {t('unk.createDevice')}
    </a>
  )
}
