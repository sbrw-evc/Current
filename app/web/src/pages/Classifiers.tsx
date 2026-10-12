import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowDown, ArrowUp, FlaskConical, Plus, Trash2 } from 'lucide-react'
import { get, post, put } from '../api/client'
import type { ClassifierKind, Classifiers } from '../api/types'
import { errorText, useT, type Dict } from '../i18n'
import { Page } from '../shell/Page'
import { useSession } from '../shell/session'
import { notify } from '../ui/notify'
import { Banner, Button, Card, Loading, Segmented } from '../ui/ui'

const strings: Dict = {
  en: {
    'cls.sub': 'CEL rules that set what Inventory DB does not know: roles, sites, boundaries, providers',
    'kind.exporter': 'Exporters',
    'kind.interface': 'Interfaces',
    'cls.rules': 'Rules',
    'cls.rules.text': 'Rules run top to bottom for every new exporter or interface; a rule that classifies stops nothing, later rules may refine. Values from Inventory DB take precedence.',
    'cls.add': 'Add a rule',
    'cls.empty': 'No rules: values come only from Inventory DB.',
    'cls.up': 'Move up',
    'cls.down': 'Move down',
    'cls.remove': 'Remove',
    'cls.saved': 'Rules saved',
    'cls.dirty': 'Unsaved changes',
    'cls.preview': 'Preview',
    'cls.preview.text': 'Run the rules of this list against a sample and see what they set.',
    'cls.sample': 'Sample (JSON)',
    'cls.run': 'Run',
    'cls.result': 'Result',
    'cls.matched': 'Rules applied: {list}',
    'cls.badjson': 'The sample is not valid JSON.',
    'cls.readonly': 'Read only: your role can view the rules but not change them.',
    'cls.help': 'Functions: ClassifyRole, ClassifySite, ClassifyGroup, ClassifyRegion, ClassifyTenant (exporters); ClassifyExternal, ClassifyInternal, ClassifyConnectivity, ClassifyProvider, ClassifyName, ClassifyDescription (interfaces).',
  },
  ru: {
    'cls.sub': 'Правила CEL задают то, чего не знает Inventory DB: роли, площадки, границы, провайдеров',
    'kind.exporter': 'Экспортёры',
    'kind.interface': 'Интерфейсы',
    'cls.rules': 'Правила',
    'cls.rules.text': 'Правила выполняются сверху вниз для каждого нового экспортёра или интерфейса; сработавшее правило не останавливает следующие, они могут уточнить значения. Данные Inventory DB важнее правил.',
    'cls.add': 'Добавить правило',
    'cls.empty': 'Правил нет: значения берутся только из Inventory DB.',
    'cls.up': 'Выше',
    'cls.down': 'Ниже',
    'cls.remove': 'Удалить',
    'cls.saved': 'Правила сохранены',
    'cls.dirty': 'Есть несохранённые изменения',
    'cls.preview': 'Проверка',
    'cls.preview.text': 'Выполните правила этого списка на примере и посмотрите, что они зададут.',
    'cls.sample': 'Пример (JSON)',
    'cls.run': 'Выполнить',
    'cls.result': 'Результат',
    'cls.matched': 'Сработали правила: {list}',
    'cls.badjson': 'Пример — некорректный JSON.',
    'cls.readonly': 'Только просмотр: ваша роль не позволяет менять правила.',
    'cls.help': 'Функции: ClassifyRole, ClassifySite, ClassifyGroup, ClassifyRegion, ClassifyTenant (экспортёры); ClassifyExternal, ClassifyInternal, ClassifyConnectivity, ClassifyProvider, ClassifyName, ClassifyDescription (интерфейсы).',
  },
}

const SAMPLES: Record<ClassifierKind, string> = {
  exporter: JSON.stringify({ address: '10.0.0.1', name: 'edge-msk-01' }, null, 2),
  interface: JSON.stringify({ exporter: { address: '10.0.0.1', name: 'edge-msk-01' }, index: 500, name: 'HundredGigE0/0/0/1', description: 'Transit: Rostelecom 100G', speed: 100000000000 }, null, 2),
}

export default function ClassifiersPage() {
  const t = useT(strings)
  const qc = useQueryClient()
  const { can } = useSession()
  const canEdit = can('settings.classifiers:edit')
  const q = useQuery({ queryKey: ['classifiers'], queryFn: ({ signal }) => get<Classifiers>('/api/classifiers', signal) })
  const [kind, setKind] = useState<ClassifierKind>('interface')
  const [draft, setDraft] = useState<Classifiers | null>(null)
  useEffect(() => {
    if (q.data) setDraft(q.data)
  }, [q.data])
  const save = useMutation({
    mutationFn: (c: Classifiers) => put<Classifiers>('/api/classifiers', c),
    onSuccess: (c) => {
      qc.setQueryData(['classifiers'], c)
      notify('ok', t('cls.saved'))
    },
    onError: (e) => notify('error', errorText(t, e).message, errorText(t, e).detail),
  })
  const dirty = !!draft && !!q.data && JSON.stringify(draft) !== JSON.stringify(q.data)
  const rules = draft?.[kind] ?? []
  const setRules = (r: string[]) => draft && setDraft({ ...draft, [kind]: r })
  const move = (i: number, d: number) => {
    const n = [...rules]
    ;[n[i], n[i + d]] = [n[i + d], n[i]]
    setRules(n)
  }

  return (
    <Page
      id="classifiers"
      wide
      subtitle={t('cls.sub')}
      actions={
        canEdit && (
          <>
            {dirty && <span className="hint">{t('cls.dirty')}</span>}
            <Button variant="primary" disabled={!dirty} busy={save.isPending} onClick={() => draft && save.mutate({ exporter: draft.exporter.filter((r) => r.trim()), interface: draft.interface.filter((r) => r.trim()) })}>
              {t('save')}
            </Button>
          </>
        )
      }
    >
      <Segmented<ClassifierKind>
        label={t('cls.rules')}
        value={kind}
        onChange={setKind}
        options={(['exporter', 'interface'] as const).map((k) => ({ value: k, label: `${t(`kind.${k}`)} · ${draft?.[k].length ?? 0}` }))}
      />
      {q.error && <Banner kind="error" title={errorText(t, q.error).message} />}
      {!canEdit && <Banner kind="info" title={t('cls.readonly')} />}
      {q.isPending || !draft ? (
        <Loading />
      ) : (
        <div className="split">
          <Card title={t('cls.rules')}>
            <p className="muted">{t('cls.rules.text')}</p>
            {rules.length === 0 && <p className="hint">{t('cls.empty')}</p>}
            <ol className="rule-list">
              {rules.map((r, i) => (
                <li key={i} className="rule">
                  <span className="rule-num">{i + 1}</span>
                  <textarea
                    className="input textarea rule-text"
                    value={r}
                    spellCheck={false}
                    readOnly={!canEdit}
                    rows={Math.min(6, Math.max(2, Math.ceil(r.length / 70)))}
                    onChange={(e) => setRules(rules.map((x, j) => (j === i ? e.target.value : x)))}
                  />
                  {canEdit && (
                    <div className="rule-actions">
                      <button type="button" className="icon-btn" disabled={i === 0} onClick={() => move(i, -1)} aria-label={t('cls.up')} title={t('cls.up')}>
                        <ArrowUp size={15} />
                      </button>
                      <button type="button" className="icon-btn" disabled={i === rules.length - 1} onClick={() => move(i, 1)} aria-label={t('cls.down')} title={t('cls.down')}>
                        <ArrowDown size={15} />
                      </button>
                      <button type="button" className="icon-btn danger-icon" onClick={() => setRules(rules.filter((_, j) => j !== i))} aria-label={t('cls.remove')} title={t('cls.remove')}>
                        <Trash2 size={15} />
                      </button>
                    </div>
                  )}
                </li>
              ))}
            </ol>
            {canEdit && (
              <div>
                <Button variant="secondary" onClick={() => setRules([...rules, ''])}>
                  <Plus size={15} /> {t('cls.add')}
                </Button>
              </div>
            )}
            <p className="hint">{t('cls.help')}</p>
          </Card>
          <Preview key={kind} kind={kind} rules={rules} />
        </div>
      )}
    </Page>
  )
}

function Preview({ kind, rules }: { kind: ClassifierKind; rules: string[] }) {
  const t = useT(strings)
  const [sample, setSample] = useState(SAMPLES[kind])
  const [bad, setBad] = useState(false)
  const run = useMutation({ mutationFn: (s: unknown) => post<Record<string, unknown>>('/api/classifiers/preview', { kind, rules: rules.filter((r) => r.trim()), sample: s }) })
  const go = () => {
    try {
      const s = JSON.parse(sample)
      setBad(false)
      run.mutate(s)
    } catch {
      setBad(true)
    }
  }
  const res = run.data
  const matched = Array.isArray(res?.matched) ? (res.matched as number[]) : null
  const result = res && typeof res.result === 'object' ? res.result : res
  return (
    <Card title={t('cls.preview')} className="side-card">
      <p className="muted">{t('cls.preview.text')}</p>
      <div className="field">
        <label>{t('cls.sample')}</label>
        <textarea className="input textarea" rows={kind === 'interface' ? 10 : 5} value={sample} spellCheck={false} onChange={(e) => setSample(e.target.value)} aria-invalid={bad} />
      </div>
      {bad && <p className="filter-status bad">{t('cls.badjson')}</p>}
      <div>
        <Button variant="secondary" onClick={go} busy={run.isPending}>
          {!run.isPending && <FlaskConical size={15} />}
          {t('cls.run')}
        </Button>
      </div>
      {run.error && <Banner kind="error" title={errorText(t, run.error).message}>{errorText(t, run.error).detail}</Banner>}
      {res && res.ok === false && <Banner kind="error" title={String(res.error ?? '')} />}
      {res && res.ok !== false && (
        <div className="stack preview-result">
          <span className="opt-label">{t('cls.result')}</span>
          {matched && <p className="hint">{t('cls.matched', { list: matched.join(', ') })}</p>}
          <pre className="code-block">{JSON.stringify(result, null, 2)}</pre>
        </div>
      )}
    </Card>
  )
}
