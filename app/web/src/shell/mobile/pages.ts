import { ALL_PAGES, owns, type PageDef } from '../nav'

// The pages an engineer on duty needs away from the desk (as Umbrella's mobilePages): how the
// traffic looks now, what the detector reports, whether the exporters send flows, and a chart.
// Everything else (flow search tables, the dependency graph, rule editors and settings) is made for
// a computer: the phone shows a note and opens it only on request.
export const MOBILE_PAGES = new Set(['home', 'detector-status', 'exporters', 'visualize'])

// The tab bar: the overview, then the first of each slot the user may open, then "More".
export const TAB_SLOTS: string[][] = [['detector-status'], ['exporters'], ['visualize']]

export function mobileReady(p: PageDef) {
  return MOBILE_PAGES.has(p.id)
}

// pageOf is the page that owns the path; the longest path wins (/detector/rules/x → Rules).
export function pageOf(path: string): PageDef | undefined {
  return [...ALL_PAGES].sort((a, b) => b.path.length - a.path.length).find((p) => owns(p, path))
}
