function initials(name: string) {
  return name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((p) => p[0]?.toUpperCase() ?? '')
    .join('')
}

function hue(s: string) {
  let h = 0
  for (const ch of s) h = (h * 31 + ch.codePointAt(0)!) % 360
  return h
}

export function Avatar({ name, username, size = 32 }: { name: string; username: string; size?: number }) {
  return (
    <span className="avatar avatar-initials" style={{ width: size, height: size, fontSize: size * 0.4, background: `hsl(${hue(username)} 55% 45%)` }} aria-hidden>
      {initials(name || username)}
    </span>
  )
}
