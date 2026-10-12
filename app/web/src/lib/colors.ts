// Series colours: the validated 8-slot categorical palette (blue, orange, aqua, yellow, magenta,
// green, violet, red) stepped for each theme, then the same hues one step lighter/darker for
// series 9-16 and so on. "Other" is always grey. Colours follow the series position in the
// response, which is ordered by volume.

const LIGHT = ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4', '#008300', '#6250d6', '#e34948']
const DARK = ['#3987e5', '#d95926', '#199e70', '#c98500', '#d55181', '#2f9e2f', '#9085e9', '#e66767']
const LIGHT2 = ['#86b6ef', '#f4a37f', '#7fd6b4', '#f5c860', '#f2b3cb', '#5fb35f', '#a59be9', '#ef9796']
const DARK2 = ['#1c5cab', '#a8441c', '#127556', '#946200', '#a33b62', '#1f6b1f', '#6a5ec4', '#b04a4a']

export function seriesColor(i: number, dark: boolean, other = false) {
  if (other) return dark ? '#5b6475' : '#a3acba'
  const base = dark ? DARK : LIGHT
  const alt = dark ? DARK2 : LIGHT2
  const set = Math.floor(i / 8) % 2 === 0 ? base : alt
  return set[i % 8]
}

export function isOther(row: string[]) {
  return row.length > 0 && row.every((v) => v === 'Other')
}
