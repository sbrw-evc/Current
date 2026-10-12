import type { PasswordPolicy } from './types'

export const DEFAULT_POLICY: PasswordPolicy = { min_length: 12, letters: true, digits: true, symbols: false, not_username: true }

export type Rule = 'length' | 'letters' | 'digits' | 'symbols' | 'username'

export function rules(p: PasswordPolicy): Rule[] {
  const r: Rule[] = ['length']
  if (p.letters) r.push('letters')
  if (p.digits) r.push('digits')
  if (p.symbols) r.push('symbols')
  if (p.not_username) r.push('username')
  return r
}

// failed lists the rules a password breaks.
export function failed(password: string, username: string, p: PasswordPolicy): Rule[] {
  return rules(p).filter((r) => {
    switch (r) {
      case 'length':
        return [...password].length < p.min_length
      case 'letters':
        return !/\p{L}/u.test(password)
      case 'digits':
        return !/\d/.test(password)
      case 'symbols':
        return !/[^\p{L}\d]/u.test(password)
      case 'username':
        return password === '' || (username !== '' && password.toLowerCase().includes(username.toLowerCase()))
    }
  })
}

export const USERNAME = /^[A-Za-z0-9][A-Za-z0-9._@-]{1,63}$/

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
