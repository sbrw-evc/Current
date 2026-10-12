import { useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { ChevronLeft } from 'lucide-react'
import { useSchema } from '../../api/queries'
import { useT } from '../../i18n'
import { Page } from '../../shell/Page'
import { useSession } from '../../shell/session'
import { notify } from '../../ui/notify'
import { Banner, Loading } from '../../ui/ui'
import { useDefaultRules, useRules, useSaveRules } from './api'
import { newDraft, replaceRule, toDraft, type Rule } from './model'
import { RuleForm } from './RuleForm'
import { Confirm } from './common'
import { detStrings } from './strings'
import './detector.css'

// Detector → Rules → one rule (/detector/rules/:id, /detector/rules/new).
export default function RuleEditPage() {
  const t = useT(detStrings)
  const { id = 'new' } = useParams()
  const isNew = id === 'new'
  const nav = useNavigate()
  const { can } = useSession()
  const edit = can('detector:edit')
  const q = useRules()
  const defaults = useDefaultRules()
  const schema = useSchema()
  const save = useSaveRules()
  const [deleting, setDeleting] = useState(false)
  const rules = useMemo(() => q.data?.rules ?? [], [q.data])
  const rule = isNew ? undefined : rules.find((r) => r.id === id)
  const builtin = defaults.data?.rules.find((r) => r.id === (rule?.id ?? ''))
  const taken = useMemo(() => rules.filter((r) => r.id !== rule?.id).map((r) => r.id), [rules, rule])

  const onSave = async (r: Rule) => {
    await save.mutateAsync(replaceRule(rules, rule?.id ?? null, r))
    notify('ok', t('rules.saved'))
    nav('/detector/rules')
  }

  return (
    <Page
      id="detector-rules"
      wide
      title={isNew ? t('form.new') : t('form.edit', { name: rule?.name ?? id })}
      subtitle={
        <Link to="/detector/rules" className="det-back">
          <ChevronLeft size={15} /> {t('form.back')}
        </Link>
      }
    >
      {q.isPending || schema.isPending ? (
        <Loading />
      ) : !isNew && !rule ? (
        <Banner kind="warn" title={t('form.notfound')} />
      ) : (
        <RuleForm
          key={rule?.id ?? 'new'}
          initial={rule ? toDraft(rule) : newDraft()}
          isNew={isNew}
          takenIds={taken}
          builtin={builtin}
          columns={schema.data?.columns ?? []}
          readOnly={!edit}
          onSave={onSave}
          onCancel={() => nav('/detector/rules')}
          onDelete={rule ? () => setDeleting(true) : undefined}
        />
      )}
      <Confirm
        open={deleting}
        title={t('rules.delete.title', { name: rule?.name ?? '' })}
        text={t('rules.delete.text')}
        action={t('delete')}
        danger
        busy={save.isPending}
        onClose={() => setDeleting(false)}
        onConfirm={() => {
          if (!rule) return
          save.mutate(
            rules.filter((r) => r.id !== rule.id),
            {
              onSuccess: () => {
                notify('ok', t('rules.deleted'))
                nav('/detector/rules')
              },
              onSettled: () => setDeleting(false),
            },
          )
        }}
      />
    </Page>
  )
}
