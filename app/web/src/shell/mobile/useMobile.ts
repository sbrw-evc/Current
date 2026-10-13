import { useSyncExternalStore } from 'react'

// The phone layout (Umbrella's useMobile): below this width the application shows the mobile shell
// (a top bar with the page title, a tab bar at the bottom) instead of the sidebar. CSS uses the
// same width.
export const MOBILE_QUERY = '(max-width: 860px)'

function subscribe(notify: () => void) {
  const mq = window.matchMedia(MOBILE_QUERY)
  mq.addEventListener('change', notify)
  return () => mq.removeEventListener('change', notify)
}

export function isMobile() {
  return window.matchMedia(MOBILE_QUERY).matches
}

export function useMobile() {
  return useSyncExternalStore(subscribe, isMobile, () => false)
}
