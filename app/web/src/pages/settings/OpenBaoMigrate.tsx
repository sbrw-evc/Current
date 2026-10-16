import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowRightLeft, CheckCircle2, PlugZap, XCircle } from 'lucide-react'
import { post } from '../../api/client'
import { errorText, useLocale, useT, type Dict } from '../../i18n'
import { num } from '../../lib/format'
import { notify } from '../../ui/notify'
import { Banner, Button, Card, Field, Input, Modal, Password, Segmented, Switch, Textarea } from '../../ui/ui'

// Settings → OpenBao → "Move to another OpenBao", as in Beacon (app/settings/openbao/Migration):
// check the target, copy every secret of the current mount there, point the references to the new
// mount and switch Current to the new connection without a restart. The old OpenBao keeps its copy.

const strings: Dict = {
  en: {
    'mv.title': 'Move to another OpenBao',
    'mv.text': 'Copies every secret of the current mount to the target, rewrites the references in PostgreSQL and flow.json, and switches Current to the new connection at once. The current OpenBao keeps its copy; other Current processes (separate roles) switch on their next restart.',
    'mv.addr': 'Target address',
    'mv.mount': 'KV v2 mount',
    'mv.namespace': 'Namespace',
    'mv.auth': 'Authentication',
    'mv.token': 'Token',
    'mv.role': 'Role ID',
    'mv.secret': 'Secret ID',
    'mv.creds.hint': 'Leave empty to reuse the current credentials on the same server.',
    'mv.ca': 'CA certificate (PEM)',
    'mv.skip': 'Do not verify the TLS certificate',
    'mv.optional': 'optional',
    'mv.check': 'Check target',
    'mv.check.ok': 'The target answers and is writable: OpenBao {version}, {secrets} secrets already in the mount',
    'mv.check.fail': 'The target is not usable',
    'mv.same': 'This is the current mount.',
    'mv.move': 'Move secrets',
    'mv.confirm': 'Move the secrets',
    'mv.confirm.text': 'Current will copy its secrets to {target} and switch to it. Keep the current OpenBao until every Current process has been restarted.',
    'mv.overwrite': 'Overwrite the {n} secrets already in the target mount',
    'mv.done': 'Moved: {copied} secrets copied, {refs} references updated',
  },
  ru: {
    'mv.title': 'Перенос в другой OpenBao',
    'mv.text': 'Копирует все секреты текущего хранилища в целевое, переписывает ссылки в PostgreSQL и flow.json и сразу переключает Current на новое подключение. В текущем OpenBao копия остаётся; другие процессы Current (отдельные роли) переключатся при следующем перезапуске.',
    'mv.addr': 'Адрес целевого OpenBao',
    'mv.mount': 'Хранилище KV v2',
    'mv.namespace': 'Namespace',
    'mv.auth': 'Аутентификация',
    'mv.token': 'Токен',
    'mv.role': 'Role ID',
    'mv.secret': 'Secret ID',
    'mv.creds.hint': 'Оставьте пустым, чтобы использовать текущие учётные данные на том же сервере.',
    'mv.ca': 'Сертификат CA (PEM)',
    'mv.skip': 'Не проверять сертификат TLS',
    'mv.optional': 'необязательно',
    'mv.check': 'Проверить',
    'mv.check.ok': 'Целевой OpenBao отвечает и доступен на запись: версия {version}, секретов в хранилище уже {secrets}',
    'mv.check.fail': 'Целевой OpenBao не подходит',
    'mv.same': 'Это текущее хранилище.',
    'mv.move': 'Перенести секреты',
    'mv.confirm': 'Перенос секретов',
    'mv.confirm.text': 'Current скопирует секреты в {target} и переключится на него. Не выключайте текущий OpenBao, пока все процессы Current не будут перезапущены.',
    'mv.overwrite': 'Перезаписать {n} секретов, уже лежащих в целевом хранилище',
    'mv.done': 'Перенесено: скопировано секретов {copied}, обновлено ссылок {refs}',
  },
}

type Target = { addr: string; mount: string; namespace: string; auth: 'approle' | 'token'; token: string; role_id: string; secret_id: string; ca_cert: string; skip_verify: boolean }
type Probe = { ok: boolean; error?: string; kv2_error?: string; secrets: number; same?: boolean; status?: { version?: string } }
type Moved = { addr: string; mount: string; copied: number; refs: number }

const EMPTY: Target = { addr: '', mount: 'flow', namespace: '', auth: 'approle', token: '', role_id: '', secret_id: '', ca_cert: '', skip_verify: false }

export function OpenBaoMigrate() {
  const t = useT(strings)
  const { locale } = useLocale()
  const qc = useQueryClient()
  const [draft, setDraft] = useState<Target>(EMPTY)
  const [probe, setProbe] = useState<Probe | null>(null)
  const [confirm, setConfirm] = useState(false)
  const [overwrite, setOverwrite] = useState(false)
  const set = (v: Partial<Target>) => {
    setDraft({ ...draft, ...v })
    setProbe(null)
  }
  const body = () => {
    const { auth, token, role_id, secret_id, ...rest } = draft
    return { ...rest, auth, ...(auth === 'token' ? { token } : { role_id, secret_id }) }
  }
  const check = useMutation({
    mutationFn: () => post<Probe>('/api/settings/openbao/probe', body()),
    onSuccess: setProbe,
    onError: (e) => setProbe({ ok: false, secrets: 0, error: errorText(t, e).detail ?? errorText(t, e).message }),
  })
  const move = useMutation({
    mutationFn: () => post<Moved>('/api/settings/openbao/migrate', { target: body(), overwrite }),
    onSuccess: (m) => {
      setConfirm(false)
      setDraft(EMPTY)
      setProbe(null)
      void qc.invalidateQueries({ queryKey: ['openbao'] })
      notify('ok', t('mv.done', { copied: m.copied, refs: m.refs }))
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })
  const addrOk = /^https?:\/\/[^/\s]+/i.test(draft.addr.trim())
  const ready = probe?.ok === true && !probe.same
  return (
    <Card title={t('mv.title')} actions={<ArrowRightLeft size={18} className="muted" />}>
      <p className="muted">{t('mv.text')}</p>
      <div className="stack">
        <Field label={t('mv.addr')}>{(id) => <Input id={id} value={draft.addr} placeholder="https://openbao-new.example:8200" spellCheck={false} onChange={(e) => set({ addr: e.target.value })} />}</Field>
        <Field label={t('mv.mount')}>{(id) => <Input id={id} value={draft.mount} spellCheck={false} onChange={(e) => set({ mount: e.target.value })} />}</Field>
        <Field label={t('mv.namespace')} optional={t('mv.optional')}>
          {(id) => <Input id={id} value={draft.namespace} spellCheck={false} onChange={(e) => set({ namespace: e.target.value })} />}
        </Field>
        <Segmented
          label={t('mv.auth')}
          value={draft.auth}
          onChange={(auth) => set({ auth })}
          options={[
            { value: 'approle', label: 'AppRole' },
            { value: 'token', label: t('mv.token') },
          ]}
        />
        {draft.auth === 'token' ? (
          <Field label={t('mv.token')} hint={t('mv.creds.hint')}>
            {(id) => <Password id={id} value={draft.token} autoComplete="off" onChange={(e) => set({ token: e.target.value })} />}
          </Field>
        ) : (
          <>
            <Field label={t('mv.role')} hint={t('mv.creds.hint')}>{(id) => <Input id={id} value={draft.role_id} spellCheck={false} onChange={(e) => set({ role_id: e.target.value })} />}</Field>
            <Field label={t('mv.secret')}>{(id) => <Password id={id} value={draft.secret_id} autoComplete="off" onChange={(e) => set({ secret_id: e.target.value })} />}</Field>
          </>
        )}
        <Field label={t('mv.ca')} optional={t('mv.optional')}>
          {(id) => <Textarea id={id} rows={3} value={draft.ca_cert} spellCheck={false} placeholder="-----BEGIN CERTIFICATE-----" onChange={(e) => set({ ca_cert: e.target.value })} />}
        </Field>
        <Switch checked={draft.skip_verify} onChange={(skip_verify) => set({ skip_verify })} label={t('mv.skip')} />
        {probe && (
          <div className={`test-result ${probe.ok && !probe.same ? 'good' : 'bad'}`}>
            {probe.ok && !probe.same ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
            <span>
              {probe.same
                ? t('mv.same')
                : probe.ok
                  ? t('mv.check.ok', { version: probe.status?.version ?? '?', secrets: num(probe.secrets, locale) })
                  : `${t('mv.check.fail')}: ${probe.error ?? ''}`}
            </span>
          </div>
        )}
      </div>
      <div className="card-actions row">
        <Button busy={check.isPending} disabled={!addrOk || !draft.mount.trim()} onClick={() => check.mutate()}>
          {!check.isPending && <PlugZap size={15} />}
          {t('mv.check')}
        </Button>
        <Button
          variant="primary"
          disabled={!ready}
          onClick={() => {
            setOverwrite(false)
            setConfirm(true)
          }}
        >
          <ArrowRightLeft size={15} /> {t('mv.move')}
        </Button>
      </div>
      <Modal
        open={confirm}
        title={t('mv.confirm')}
        onClose={() => setConfirm(false)}
        footer={
          <>
            <Button onClick={() => setConfirm(false)}>{t('cancel')}</Button>
            <Button variant="danger" busy={move.isPending} disabled={(probe?.secrets ?? 0) > 0 && !overwrite} onClick={() => move.mutate()}>
              {t('mv.move')}
            </Button>
          </>
        }
      >
        <p>{t('mv.confirm.text', { target: `${draft.addr.trim()} / ${draft.mount.trim()}` })}</p>
        {(probe?.secrets ?? 0) > 0 && (
          <Banner kind="warn" title={t('mv.overwrite', { n: probe?.secrets ?? 0 })}>
            <Switch checked={overwrite} onChange={setOverwrite} label={t('mv.overwrite', { n: probe?.secrets ?? 0 })} />
          </Banner>
        )}
      </Modal>
    </Card>
  )
}
