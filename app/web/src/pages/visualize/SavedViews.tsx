import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Bookmark, Trash2, Users } from 'lucide-react'
import { del, get, post } from '../../api/client'
import type { SavedView } from '../../api/types'
import { errorText, useT } from '../../i18n'
import { useSession } from '../../shell/session'
import { notify } from '../../ui/notify'
import { Button, Field, Input, Modal, Switch } from '../../ui/ui'
import { fromSaved, toSaved, type VisState } from './state'
import { visStrings } from './strings'

export function SavedViews({ current, onLoad }: { current: VisState; onLoad: (s: VisState) => void }) {
  const t = useT(visStrings)
  const qc = useQueryClient()
  const { user } = useSession()
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [shared, setShared] = useState(false)
  const list = useQuery({ queryKey: ['saved-views'], queryFn: ({ signal }) => get<{ results: SavedView[] }>('/api/saved-views', signal) })
  const save = useMutation({
    mutationFn: () => post('/api/saved-views', { name: name.trim(), shared, request: toSaved(current) }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['saved-views'] })
      setOpen(false)
      setName('')
      notify('ok', t('views.saved'))
    },
    onError: (e) => notify('error', errorText(t, e).message),
  })
  const remove = useMutation({
    mutationFn: (id: string) => del(`/api/saved-views/${encodeURIComponent(id)}`),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['saved-views'] })
      notify('ok', t('views.deleted'))
    },
    onError: (e) => notify('error', errorText(t, e).message),
  })
  const views = list.data?.results ?? []
  return (
    <div className="saved-views">
      <div className="opt-label-row">
        <span className="opt-label">{t('views.title')}</span>
        <button type="button" className="link-button" onClick={() => setOpen(true)}>
          <Bookmark size={14} /> {t('views.save')}
        </button>
      </div>
      {views.length === 0 ? (
        <p className="hint">{list.isPending ? t('loading') : t('views.empty')}</p>
      ) : (
        <ul className="view-list">
          {views.map((v) => (
            <li key={v.id}>
              <button type="button" className="view-item" onClick={() => onLoad(fromSaved(v.request))} title={v.name}>
                <span className="view-name">{v.name}</span>
                {v.shared && <Users size={13} className="muted" aria-label="shared" />}
                {v.owner === user.username && <span className="view-mine">{t('views.mine')}</span>}
              </button>
              {v.owner === user.username && (
                <button
                  type="button"
                  className="icon-btn view-del"
                  aria-label={t('delete')}
                  onClick={() => window.confirm(t('views.delete', { name: v.name })) && remove.mutate(v.id)}
                >
                  <Trash2 size={14} />
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
      <Modal
        open={open}
        title={t('views.save')}
        onClose={() => setOpen(false)}
        footer={
          <>
            <Button variant="ghost" onClick={() => setOpen(false)}>
              {t('cancel')}
            </Button>
            <Button variant="primary" busy={save.isPending} disabled={!name.trim()} onClick={() => save.mutate()}>
              {t('save')}
            </Button>
          </>
        }
      >
        <Field label={t('views.name')}>{(id) => <Input id={id} value={name} onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && name.trim() && save.mutate()} />}</Field>
        <Switch checked={shared} onChange={setShared} label={t('views.shared')} hint={t('views.shared.hint')} />
      </Modal>
    </div>
  )
}
