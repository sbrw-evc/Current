import { OverlayScrollbars, type PartialOptions } from 'overlayscrollbars'
import 'overlayscrollbars/overlayscrollbars.css'

// Replaces native scrollbars with OverlayScrollbars on every scroll container
// in the app, so they look the same in Chrome, Firefox and Safari.
//
// Containers are found by their computed overflow, so no component has to opt
// in. The element itself is used as the viewport: the library adds its
// scrollbar elements but never moves React-owned children into a wrapper.
// Anything skipped here keeps the CSS-styled native scrollbars from styles.css.

const OPTIONS: PartialOptions = {
  scrollbars: {
    theme: 'os-theme-app',
    autoHide: 'never',
    clickScroll: 'instant',
  },
}

// Subtrees that manage their own scrolling (the flow canvas), opt out with
// data-native-scroll, are the library's own scrollbars, or belong to the phone
// layout, where touch scrolling shows the system's own overlay scrollbars.
const SKIP_TREE = '[data-native-scroll], .cm-editor, .os-scrollbar'
// Elements that can't host extra children.
const SKIP = `textarea, select, input, iframe, ${SKIP_TREE}`

function scrolls(el: HTMLElement) {
  const s = getComputedStyle(el)
  return /auto|scroll/.test(s.overflowX) || /auto|scroll/.test(s.overflowY)
}

function attach(el: Element) {
  if (!(el instanceof HTMLElement) || el === document.body || el === document.documentElement) return
  if (el.matches(SKIP) || OverlayScrollbars(el) || !scrolls(el)) return
  OverlayScrollbars({ target: el, elements: { viewport: el } }, OPTIONS)
}

function scan(root: Element) {
  attach(root)
  for (const el of root.querySelectorAll('*')) if (!el.closest(SKIP_TREE)) attach(el)
}

export function installScrollbars() {
  if (typeof window === 'undefined' || !('MutationObserver' in window)) return

  const pending = new Set<Element>()
  const removed = new Set<Element>()
  let frame = 0
  const flush = () => {
    frame = 0
    // Free instances whose element left the page (route change, closed modal).
    for (const el of removed) {
      if (el.isConnected) continue
      for (const t of [el, ...el.querySelectorAll('[data-overlayscrollbars]')]) OverlayScrollbars(t as HTMLElement)?.destroy()
    }
    removed.clear()
    for (const el of pending) if (el.isConnected) scan(el)
    pending.clear()
  }
  const queue = (el: Element) => {
    if (el.closest(SKIP_TREE)) return
    pending.add(el)
    frame ||= requestAnimationFrame(flush)
  }

  new MutationObserver((records) => {
    for (const r of records) {
      if (r.type === 'attributes') queue(r.target as Element)
      else {
        r.addedNodes.forEach((n) => n instanceof Element && queue(n))
        r.removedNodes.forEach((n) => {
          if (n instanceof Element && !n.closest(SKIP_TREE)) {
            removed.add(n)
            frame ||= requestAnimationFrame(flush)
          }
        })
      }
    }
  }).observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ['class'] })

  queue(document.body)
}
