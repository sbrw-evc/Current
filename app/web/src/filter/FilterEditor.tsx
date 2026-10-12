import { useEffect, useRef } from 'react'
import { autocompletion, closeBrackets, completionKeymap, type Completion, type CompletionContext as CMContext, type CompletionResult } from '@codemirror/autocomplete'
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands'
import { linter, type Diagnostic } from '@codemirror/lint'
import { EditorState } from '@codemirror/state'
import { EditorView, keymap, placeholder as placeholderExt } from '@codemirror/view'
import { post } from '../api/client'
import type { CompleteResult, ValidateResult } from '../api/types'
import { completionContext } from './lexer'
import { filterHighlight, filterLanguage } from './language'

// The filter editor: the filter language with highlighting, completion of columns, operators and
// values from POST /api/filter/complete, and errors from POST /api/filter/validate as you type.

async function complete(ctx: CMContext): Promise<CompletionResult | null> {
  const text = ctx.state.doc.toString()
  const c = completionContext(text, ctx.pos)
  if (!ctx.explicit && c.prefix === '' && c.what !== 'value' && c.what !== 'operator') {
    // Open by itself only while typing a word, or right after a column or an operator.
    const before = text.slice(0, ctx.pos)
    if (!/[\s(]$/.test(before) || c.what === 'logic') return null
  }
  if (c.what === 'logic') {
    const opts = ['AND', 'OR', 'AND NOT', 'OR NOT'].filter((k) => k.startsWith(c.prefix.toUpperCase()))
    return { from: c.from, options: opts.map((k) => ({ label: k, type: 'keyword' })), validFor: /^\w*$/ }
  }
  let r: CompleteResult
  try {
    r = await post<CompleteResult>('/api/filter/complete', { what: c.what, column: c.column, prefix: c.prefix.replace(/^['"]/, '') })
  } catch {
    return null
  }
  if (ctx.aborted) return null
  const options: Completion[] = r.completions.map((x) => ({
    label: x.label,
    detail: x.detail,
    type: c.what === 'column' ? 'variable' : c.what === 'operator' ? 'keyword' : x.quoted ? 'text' : 'constant',
    apply: (c.what === 'value' && x.quoted ? `'${x.label.replace(/'/g, "\\'")}'` : x.label) + (c.what === 'value' ? '' : ' '),
  }))
  return { from: c.from, options, filter: false }
}

export type FilterStatus = { valid: boolean; message?: string; checking: boolean }

export function FilterEditor({
  value,
  onChange,
  onSubmit,
  onStatus,
  placeholder,
  readOnly,
}: {
  value: string
  onChange: (v: string) => void
  onSubmit?: () => void
  onStatus?: (s: FilterStatus) => void
  placeholder?: string
  readOnly?: boolean
}) {
  const host = useRef<HTMLDivElement>(null)
  const view = useRef<EditorView | null>(null)
  const cb = useRef({ onChange, onSubmit, onStatus })
  cb.current = { onChange, onSubmit, onStatus }

  useEffect(() => {
    const lint = linter(
      async (v): Promise<Diagnostic[]> => {
        const text = v.state.doc.toString()
        if (!text.trim()) {
          cb.current.onStatus?.({ valid: true, checking: false })
          return []
        }
        cb.current.onStatus?.({ valid: true, checking: true })
        try {
          const r = await post<ValidateResult>('/api/filter/validate', { filter: text })
          cb.current.onStatus?.({ valid: r.valid, message: r.errors[0]?.message, checking: false })
          return r.errors.map((e) => {
            const from = Math.min(Math.max(0, e.offset), text.length)
            const word = /^[^\s()',]+/.exec(text.slice(from))
            return { from, to: Math.min(text.length, from + Math.max(1, word?.[0].length ?? 1)), severity: 'error', message: e.message }
          })
        } catch {
          cb.current.onStatus?.({ valid: true, checking: false })
          return []
        }
      },
      { delay: 450 },
    )
    const v = new EditorView({
      parent: host.current!,
      state: EditorState.create({
        doc: value,
        extensions: [
          history(),
          closeBrackets(),
          filterLanguage,
          filterHighlight,
          EditorView.lineWrapping,
          placeholderExt(placeholder ?? ''),
          EditorState.readOnly.of(!!readOnly),
          autocompletion({ override: [complete], activateOnTyping: true, icons: false }),
          lint,
          keymap.of([
            {
              key: 'Mod-Enter',
              run: () => {
                cb.current.onSubmit?.()
                return true
              },
            },
            ...completionKeymap,
            ...historyKeymap,
            ...defaultKeymap,
          ]),
          EditorView.updateListener.of((u) => {
            if (u.docChanged) cb.current.onChange(u.state.doc.toString())
          }),
          EditorView.contentAttributes.of({ 'aria-label': 'filter', spellcheck: 'false' }),
        ],
      }),
    })
    view.current = v
    return () => {
      v.destroy()
      view.current = null
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    const v = view.current
    if (v && v.state.doc.toString() !== value) v.dispatch({ changes: { from: 0, to: v.state.doc.length, insert: value } })
  }, [value])

  return <div ref={host} className="filter-editor" />
}
