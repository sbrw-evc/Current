import type { MouseEvent } from 'react'

export type Origin = { x: number; y: number }

export function reducedMotion() {
  try {
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches
  } catch {
    return false
  }
}

export function originOf(e: MouseEvent<HTMLElement>): Origin {
  const r = e.currentTarget.getBoundingClientRect()
  return { x: r.left + r.width / 2, y: r.top + r.height / 2 }
}

type ViewTransition = { ready: Promise<void>; finished: Promise<void> }

export function viewTransition(update: () => void): ViewTransition | null {
  const doc = document as Document & { startViewTransition?: (cb: () => void) => ViewTransition }
  if (typeof doc.startViewTransition !== 'function') return null
  return doc.startViewTransition(update)
}
