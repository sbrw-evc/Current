import { HighlightStyle, StreamLanguage, syntaxHighlighting } from '@codemirror/language'
import { tags } from '@lezer/highlight'

// Syntax highlighting of the filter language. A word is a column when an operator follows it.
const OPERATOR_AHEAD = /^\s*(<<|!=|<=|>=|=|<|>|NOTIN\b|IN\b|UNLIKE\b|IUNLIKE\b|ILIKE\b|LIKE\b)/i
const KEYWORD = /^(AND|OR|NOT|IN|NOTIN|LIKE|UNLIKE|ILIKE|IUNLIKE)$/i

type State = { comment: boolean }

export const filterLanguage = StreamLanguage.define<State>({
  name: 'flowfilter',
  startState: () => ({ comment: false }),
  token(stream, state) {
    if (state.comment) {
      if (stream.skipTo('*/')) {
        stream.pos += 2
        state.comment = false
      } else stream.skipToEnd()
      return 'comment'
    }
    if (stream.eatSpace()) return null
    if (stream.match('--')) {
      stream.skipToEnd()
      return 'comment'
    }
    if (stream.match('/*')) {
      state.comment = true
      return 'comment'
    }
    const ch = stream.peek()
    if (ch === "'" || ch === '"') {
      stream.next()
      let escaped = false
      let c: string | void
      while ((c = stream.next()) != null) {
        if (c === ch && !escaped) break
        escaped = !escaped && c === '\\'
      }
      return 'string'
    }
    if (stream.match(/^(<<|!=|<=|>=|=|<|>)/)) return 'operator'
    if (stream.match(/^[(),]/)) return 'punctuation'
    if (stream.match(/^[0-9a-fA-F]*[:.][0-9a-fA-F:.]+(\/\d+)?/)) return 'atom'
    if (stream.match(/^AS\d+\b/i)) return 'atom'
    if (stream.match(/^\d+(\.\d+)?\b/)) return 'number'
    if (stream.match(/^[A-Za-z_][A-Za-z0-9_]*/)) {
      const w = stream.current()
      if (KEYWORD.test(w)) return 'keyword'
      if (stream.match(OPERATOR_AHEAD, false)) return 'variableName'
      return 'atom'
    }
    stream.next()
    return 'invalid'
  },
  tokenTable: {},
})

export const filterHighlight = syntaxHighlighting(
  HighlightStyle.define([
    { tag: tags.keyword, color: 'var(--cm-keyword)', fontWeight: '600' },
    { tag: tags.variableName, color: 'var(--cm-column)' },
    { tag: tags.string, color: 'var(--cm-string)' },
    { tag: tags.number, color: 'var(--cm-number)' },
    { tag: tags.atom, color: 'var(--cm-atom)' },
    { tag: tags.operator, color: 'var(--cm-operator)' },
    { tag: tags.comment, color: 'var(--muted)', fontStyle: 'italic' },
    { tag: tags.invalid, color: 'var(--error)' },
  ]),
)
