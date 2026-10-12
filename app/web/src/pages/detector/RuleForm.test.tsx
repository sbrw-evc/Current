import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError } from '../../api/client'
import { LocaleProvider } from '../../i18n'
import { columns } from '../../mock/schema'
import { newDraft, toDraft, type Rule } from './model'
import { RuleForm } from './RuleForm'

// The filter editor (CodeMirror + /api/filter/*) is replaced by a plain textarea.
vi.mock('../../filter/FilterEditor', () => ({
  FilterEditor: ({ value, onChange }: { value: string; onChange: (v: string) => void }) => <textarea aria-label="filter" value={value} onChange={(e) => onChange(e.target.value)} />,
}))

;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

let host: HTMLDivElement
let root: Root

beforeEach(() => {
  host = document.createElement('div')
  document.body.appendChild(host)
  root = createRoot(host)
})

afterEach(() => {
  act(() => root.unmount())
  host.remove()
})

function render(props: Partial<Parameters<typeof RuleForm>[0]> & { onSave: (r: Rule) => Promise<unknown> }) {
  act(() =>
    root.render(
      <LocaleProvider initial="en">
        <RuleForm initial={newDraft('link_utilization')} isNew takenIds={['ddos-syn']} columns={columns} onCancel={() => {}} {...props} />
      </LocaleProvider>,
    ),
  )
}

// type sets an input's value the way React notices it.
function type(el: HTMLInputElement | HTMLTextAreaElement, value: string) {
  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype
  Object.getOwnPropertyDescriptor(proto, 'value')!.set!.call(el, value)
  el.dispatchEvent(new Event('input', { bubbles: true }))
}

function input(label: string): HTMLInputElement {
  const l = [...host.querySelectorAll('label')].find((x) => x.textContent?.trim() === label)
  if (!l) throw new Error(`no field ${label}`)
  return host.querySelector<HTMLInputElement>(`[id="${l.htmlFor}"]`)!
}

async function submit() {
  await act(async () => {
    host.querySelector<HTMLButtonElement>('button[type=submit]')!.click()
  })
}

const errors = () => [...host.querySelectorAll('.det-field-error')].map((e) => e.textContent)

describe('RuleForm', () => {
  it('checks the fields before saving and builds the rule', async () => {
    const onSave = vi.fn(async (_r: Rule) => {})
    render({ onSave })
    await submit()
    expect(onSave).not.toHaveBeenCalled()
    expect(errors()).toEqual(expect.arrayContaining(['Required.', 'Lower-case letters, digits, ".", "_", "-", up to 64.']))
    expect(host.textContent).toContain('Fix the highlighted fields.')

    act(() => type(input('Name'), 'Uplinks hot'))
    expect(input('Identifier').value).toBe('uplinks-hot') // proposed from the name
    act(() => type(input('Utilization, %'), '90'))
    act(() => type(input('Every'), '5s'))
    await submit()
    expect(errors()).toEqual(['At least 10s.'])
    act(() => type(input('Every'), '30s'))
    act(() => type(host.querySelector('textarea')!, "InIfBoundary = 'external'"))
    await submit()
    expect(onSave).toHaveBeenCalledTimes(1)
    expect(onSave.mock.calls[0]).toEqual([
      { id: 'uplinks-hot', name: 'Uplinks hot', enabled: true, kind: 'link_utilization', severity: 'warning', thresholds: { percent: 90 }, interval: '30s', filter: "InIfBoundary = 'external'" },
    ])
  })

  it('shows the server validation errors on the fields', async () => {
    const onSave = vi.fn(async () => {
      throw new ApiError(400, 'invalid_rule', 'rule 2: thresholds.ratio must be in (0, 1]\nfilter: column Nope is unknown\nsomething unexpected')
    })
    const rule: Rule = { id: 'ddos-syn-2', name: 'SYN', enabled: true, kind: 'ddos_syn', filter: 'Nope = 1', thresholds: { ratio: 0.5 }, severity: 'error' }
    render({ onSave, initial: toDraft(rule), isNew: false })
    await submit()
    expect(onSave).toHaveBeenCalledTimes(1)
    expect(errors()).toEqual(expect.arrayContaining(['thresholds.ratio must be in (0, 1]', 'filter: column Nope is unknown']))
    expect(host.textContent).toContain('The server rejected the rule')
    expect(host.textContent).toContain('something unexpected')
    // editing clears the server's verdict
    act(() => type(input('Share of SYN without ACK (0–1)'), '0.6'))
    expect(errors()).toEqual([])
  })

  it('rejects an identifier used by another rule and restores built-in values', async () => {
    const onSave = vi.fn(async (_r: Rule) => {})
    const builtin: Rule = { id: 'ddos-syn', name: 'SYN flood', enabled: true, kind: 'ddos_syn', filter: "InIfBoundary = 'external'", thresholds: { ratio: 0.5, pps: 10000 }, window: '1m', severity: 'error' }
    render({ onSave, initial: toDraft({ ...builtin, thresholds: { ratio: 0.9 } }), isNew: false, takenIds: ['link-commit'], builtin })
    act(() => type(input('Identifier'), 'link-commit'))
    await submit()
    expect(errors()).toEqual(['Another rule has this identifier.'])
    const restore = [...host.querySelectorAll('button')].find((b) => b.textContent?.includes('Restore default'))!
    act(() => restore.click())
    expect(input('Identifier').value).toBe('ddos-syn')
    expect(input('Packet rate, packets/s').value).toBe('10k')
    await submit()
    expect(onSave.mock.calls[0][0]).toEqual(builtin)
  })
})
