// publicURLOk: the public address of Flow (optional) is an http(s) address without a query.
export function publicURLOk(v: string) {
  const s = v.trim()
  if (s === '') return true
  try {
    const u = new URL(s)
    return (u.protocol === 'http:' || u.protocol === 'https:') && u.host !== '' && !u.username && !u.search && !u.hash && !/[?#]/.test(s)
  } catch {
    return false
  }
}

// spaKeyOk: an SPA connection key looks like spa1.<base64url JSON>.
export function spaKeyOk(v: string) {
  return /^spa1\.[A-Za-z0-9_-]{20,}={0,2}$/.test(v.trim())
}
