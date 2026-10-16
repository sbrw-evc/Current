import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Eye, Lock, Pencil, Plus, Trash2 } from 'lucide-react'
import { del, get, post, put } from '../../api/client'
import { errorText, useLocale, useT } from '../../i18n'
import { Page } from '../../shell/Page'
import { useSession } from '../../shell/session'
import { notify } from '../../ui/notify'
import { Banner, Button, Card, Chip, Field, Input, Loading, Modal, Textarea } from '../../ui/ui'
import { allPermissions, draftOf, grouped, lockedView, NAME_MAX, normalize, perm, sameDraft, toggle, validRoleName, type Catalog, type RoleDraft, type RoleRecord } from './RolesModel'
import { rolesStrings } from './rolesStrings'

// Settings → Roles (docs/api.md "Users and roles"): the roles Flow publishes to SPA. Custom roles
// are created, changed and deleted here through /api/roles, and every change republishes the role
// catalogue to SPA on the server; built-in roles (Administrator, Viewer) are read-only. People get
// their roles in SPA.

const useCatalog = () => useQuery({ queryKey: ['access-catalog'], queryFn: ({ signal }) => get<Catalog>('/api/access/catalog', signal), staleTime: Infinity })

export default function RolesPage() {
  const t = useT(rolesStrings)
  const { can } = useSession()
  const edit = can('roles:edit')
  const roles = useQuery({ queryKey: ['roles'], queryFn: ({ signal }) => get<{ results: RoleRecord[] }>('/api/roles', signal) })
  const catalog = useCatalog()
  // null: closed; 'new': a new role; a record: that role.
  const [open, setOpen] = useState<RoleRecord | 'new' | null>(null)
  const [deleting, setDeleting] = useState<RoleRecord | null>(null)
  const qc = useQueryClient()
  const remove = useMutation({
    mutationFn: (id: number) => del(`/api/roles/${id}`),
    onSuccess: () => {
      setDeleting(null)
      void qc.invalidateQueries({ queryKey: ['roles'] })
      void qc.invalidateQueries({ queryKey: ['spa'] })
      notify('ok', t('roles.deleted'))
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })
  const total = catalog.data ? allPermissions(catalog.data).length : 0
  const error = roles.error ?? catalog.error
  return (
    <Page
      id="roles"
      subtitle={t('roles.sub')}
      actions={
        edit && (
          <Button variant="primary" disabled={!catalog.data} onClick={() => setOpen('new')}>
            <Plus size={15} /> {t('roles.new')}
          </Button>
        )
      }
    >
      {error && <Banner kind="error" title={roles.error ? errorText(t, roles.error).message : t('roles.catalog.error')} />}
      {roles.isPending ? (
        <Loading />
      ) : (
        <Card pad={false}>
          {(roles.data?.results.length ?? 0) === 0 ? (
            <p className="card-pad muted">{t('roles.none')}</p>
          ) : (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>{t('roles.col.role')}</th>
                    <th>{t('roles.col.ident')}</th>
                    <th>{t('roles.col.kind')}</th>
                    <th className="num">{t('roles.col.permissions')}</th>
                    <th className="num">{t('roles.col.users')}</th>
                    <th className="actions-col" />
                  </tr>
                </thead>
                <tbody>
                  {roles.data?.results.map((r) => {
                    const editable = edit && !r.builtin
                    return (
                      <tr key={r.id}>
                        <td>
                          <div className="cell-main">{r.name}</div>
                          {r.description && <div className="cell-sub muted">{r.description}</div>}
                        </td>
                        <td>
                          <code>{r.ident}</code>
                        </td>
                        <td>
                          {r.builtin ? (
                            <Chip tone="purple" dot={false}>
                              <Lock size={12} /> {t('roles.builtin')}
                            </Chip>
                          ) : (
                            <Chip tone="info" dot={false}>
                              {t('roles.custom')}
                            </Chip>
                          )}
                        </td>
                        <td className="num">{total ? t('roles.count', { n: r.permissions.length, total }) : r.permissions.length}</td>
                        <td className="num">{r.users}</td>
                        <td className="actions-col">
                          <div className="row">
                            <Button size="sm" disabled={!catalog.data} onClick={() => setOpen(r)}>
                              {editable ? <Pencil size={14} /> : <Eye size={14} />} {editable ? t('roles.edit') : t('roles.open')}
                            </Button>
                            {editable && (
                              <button
                                type="button"
                                className="icon-btn danger-icon"
                                aria-label={t('roles.delete')}
                                title={r.users > 0 ? t('roles.inuse', { n: r.users }) : t('roles.delete')}
                                disabled={r.users > 0}
                                onClick={() => setDeleting(r)}
                              >
                                <Trash2 size={16} />
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}
      {catalog.data && open !== null && (
        <RoleDialog key={open === 'new' ? 'new' : open.id} role={open === 'new' ? null : open} catalog={catalog.data} readOnly={!edit || (open !== 'new' && open.builtin)} onClose={() => setOpen(null)} />
      )}
      <Modal
        open={deleting !== null}
        title={t('roles.delete')}
        onClose={() => setDeleting(null)}
        footer={
          <>
            <Button onClick={() => setDeleting(null)}>{t('cancel')}</Button>
            <Button variant="danger" busy={remove.isPending} onClick={() => deleting && remove.mutate(deleting.id)}>
              {t('delete')}
            </Button>
          </>
        }
      >
        <p>{t('roles.delete.text', { name: deleting?.name ?? '', ident: deleting?.ident ?? '' })}</p>
      </Modal>
    </Page>
  )
}

function RoleDialog({ role, catalog, readOnly, onClose }: { role: RoleRecord | null; catalog: Catalog; readOnly: boolean; onClose: () => void }) {
  const t = useT(rolesStrings)
  const { locale } = useLocale()
  const qc = useQueryClient()
  const initial = { ...draftOf(role), permissions: normalize(catalog, role?.permissions ?? []) }
  const [draft, setDraft] = useState<RoleDraft>(initial)
  const save = useMutation({
    mutationFn: () => {
      const body = { name: draft.name.trim(), description: draft.description.trim(), permissions: draft.permissions }
      return role ? put<RoleRecord>(`/api/roles/${role.id}`, body) : post<RoleRecord>('/api/roles', body)
    },
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: ['roles'] })
      void qc.invalidateQueries({ queryKey: ['spa'] })
      notify('ok', t(role ? 'roles.updated' : 'roles.created', { name: r.name }))
      onClose()
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })
  const setPerms = (permissions: string[]) => setDraft({ ...draft, permissions })
  const ok = validRoleName(draft.name) && (role === null || !sameDraft(draft, initial))
  const total = allPermissions(catalog).length
  const title = readOnly ? `${t('roles.view')} · ${role?.name ?? ''}` : role ? `${t('roles.edit')} · ${role.name}` : t('roles.new')
  return (
    <Modal
      open
      title={title}
      onClose={onClose}
      footer={
        readOnly ? (
          <Button onClick={onClose}>{t('close')}</Button>
        ) : (
          <>
            <Button onClick={onClose}>{t('cancel')}</Button>
            <Button variant="primary" busy={save.isPending} disabled={!ok} onClick={() => save.mutate()}>
              {t('save')}
            </Button>
          </>
        )
      }
    >
      {role?.builtin && <Banner kind="info" title={t('roles.builtin.text')} />}
      <Field label={t('roles.field.name')} hint={readOnly ? undefined : t('roles.field.name.hint')}>
        {(id) => (
          <Input
            id={id}
            value={draft.name}
            maxLength={NAME_MAX}
            readOnly={readOnly}
            aria-invalid={draft.name !== '' && !validRoleName(draft.name)}
            onChange={(e) => setDraft({ ...draft, name: e.target.value })}
          />
        )}
      </Field>
      {role && (
        <p className="hint">
          {t('roles.col.ident')}: <code>{role.ident}</code>
        </p>
      )}
      <Field label={t('roles.field.description')} optional={readOnly ? undefined : t('roles.optional')} hint={readOnly ? undefined : t('roles.field.description.hint')}>
        {(id) => <Textarea id={id} rows={2} value={draft.description} readOnly={readOnly} onChange={(e) => setDraft({ ...draft, description: e.target.value })} />}
      </Field>
      <div className="stack" style={{ gap: 10 }}>
        <div className="row" style={{ justifyContent: 'space-between' }}>
          <div>
            <strong>{t('roles.field.permissions')}</strong> <span className="muted">{t('roles.count', { n: draft.permissions.length, total })}</span>
            {!readOnly && <div className="hint">{t('roles.field.permissions.hint')}</div>}
          </div>
        </div>
        {grouped(catalog).map(({ group, pages }) => {
          const groupPerms = pages.flatMap((p) => p.features.map((f) => perm(p.id, f.id)))
          return (
            <section key={group.id} className="stack" style={{ gap: 6 }}>
              <div className="row" style={{ justifyContent: 'space-between' }}>
                <span className="section-title">{group.title[locale]}</span>
                {!readOnly && (
                  <div className="row" style={{ gap: 6 }}>
                    <Button size="sm" variant="ghost" onClick={() => setPerms(normalize(catalog, [...draft.permissions, ...groupPerms]))}>
                      {t('roles.all')}
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => setPerms(draft.permissions.filter((x) => !groupPerms.includes(x)))}>
                      {t('roles.clear')}
                    </Button>
                  </div>
                )}
              </div>
              {pages.map((p) => (
                <div key={p.id} className="role-page">
                  <div className="cell-main">{p.title[locale]}</div>
                  {p.features.map((f) => {
                    const id = perm(p.id, f.id)
                    const checked = draft.permissions.includes(id)
                    const locked = lockedView(draft.permissions, id)
                    return (
                      <label key={f.id} className="check-row" title={id}>
                        <input
                          type="checkbox"
                          checked={checked}
                          disabled={readOnly || locked}
                          onChange={(e) => setPerms(toggle(catalog, draft.permissions, id, e.target.checked))}
                        />
                        <span>
                          {f.title[locale]} <code className="muted">{id}</code>
                        </span>
                      </label>
                    )
                  })}
                </div>
              ))}
            </section>
          )
        })}
      </div>
    </Modal>
  )
}
