// The password policy of the Umbrella family: the same JSON and checks as Umbrella Monitoring,
// Inventory DB and Network Control (docs/identity-federation.md).
import { isCommonPassword } from './commonPasswords'

export type Letters = 'latin' | 'cyrillic' | 'latin_cyrillic' | 'any'

export type PasswordPolicy = {
  min_length: number
  require_digits: boolean
  min_digits: number
  require_special: boolean
  min_special: number
  require_mixed_case: boolean
  letters: Letters
  max_age_days: number
  warn_days: number
  history_count: number
  block_common: boolean
  lockout_attempts: number
  lockout_minutes: number
}

export type Violation = 'length' | 'digits' | 'special' | 'mixed_case' | 'letters' | 'username' | 'control' | 'common' | 'history'

export const defaultPolicy: PasswordPolicy = {
  min_length: 12,
  require_digits: true,
  min_digits: 1,
  require_special: true,
  min_special: 1,
  require_mixed_case: true,
  letters: 'latin',
  max_age_days: 0,
  warn_days: 0,
  history_count: 5,
  block_common: true,
  lockout_attempts: 10,
  lockout_minutes: 15,
}

const SCRIPT: Record<Letters, RegExp | null> = {
  latin: /\p{Script=Latin}/u,
  cyrillic: /\p{Script=Cyrillic}/u,
  latin_cyrillic: /[\p{Script=Latin}\p{Script=Cyrillic}]/u,
  any: null,
}

export function checkPassword(password: string, username: string, p: PasswordPolicy): Violation[] {
  const out = new Set<Violation>()
  const chars = [...password]
  if (chars.length < p.min_length) out.add('length')
  let digits = 0
  let special = 0
  let upper = false
  let lower = false
  for (const ch of chars) {
    if (/\p{Cc}/u.test(ch)) out.add('control')
    else if (/\p{Nd}/u.test(ch)) digits++
    else if (/\p{L}/u.test(ch)) {
      const allowed = SCRIPT[p.letters]
      if (allowed && !allowed.test(ch)) out.add('letters')
      upper ||= /\p{Lu}/u.test(ch)
      lower ||= /\p{Ll}/u.test(ch)
    } else special++
  }
  if (p.require_digits && digits < p.min_digits) out.add('digits')
  if (p.require_special && special < p.min_special) out.add('special')
  if (p.require_mixed_case && (!upper || !lower)) out.add('mixed_case')
  if (username && password.trim().toLowerCase() === username.trim().toLowerCase()) out.add('username')
  if (p.block_common && isCommonPassword(password, username)) out.add('common')
  return [...out]
}

export function rules(p: PasswordPolicy): Violation[] {
  const r: Violation[] = ['length']
  if (p.require_digits) r.push('digits')
  if (p.require_special) r.push('special')
  if (p.require_mixed_case) r.push('mixed_case')
  if (p.letters !== 'any') r.push('letters')
  r.push('username')
  if (p.block_common) r.push('common')
  return r
}

export type PolicyProblem = 'length' | 'digits' | 'special' | 'fit' | 'max_age' | 'warn' | 'history' | 'lockout'

export function policyError(p: PasswordPolicy): PolicyProblem | null {
  if (p.min_length < 8 || p.min_length > 128) return 'length'
  if (p.require_digits && (p.min_digits < 1 || p.min_digits > 16)) return 'digits'
  if (p.require_special && (p.min_special < 1 || p.min_special > 16)) return 'special'
  if ((p.require_digits ? p.min_digits : 0) + (p.require_special ? p.min_special : 0) + (p.require_mixed_case ? 2 : 0) > p.min_length) return 'fit'
  if (p.max_age_days < 0 || p.max_age_days > 3650) return 'max_age'
  if (p.max_age_days > 0 && (p.warn_days < 0 || p.warn_days > 90 || p.warn_days >= p.max_age_days)) return 'warn'
  if (p.history_count < 0 || p.history_count > 24) return 'history'
  if (p.lockout_attempts !== 0 && (p.lockout_attempts < 3 || p.lockout_attempts > 100 || p.lockout_minutes < 1 || p.lockout_minutes > 1440)) return 'lockout'
  return null
}

export const policyStrings = {
  en: {
    'pp.length': 'At least {n} characters',
    'pp.digits': 'At least {n} digits',
    'pp.special': 'At least {n} special characters (! @ # - _ …)',
    'pp.mixed_case': 'Upper and lower case letters',
    'pp.letters': 'Letters: {letters}',
    'pp.username': 'Differs from the login',
    'pp.control': 'No control characters',
    'pp.common': 'Not a common password, sequence or the login with a few characters',
    'pp.history': 'Differs from the last {n} passwords',
    'pp.match': 'Passwords match',
    'pp.letters.latin': 'Latin only',
    'pp.letters.cyrillic': 'Cyrillic only',
    'pp.letters.latin_cyrillic': 'Latin and Cyrillic',
    'pp.letters.any': 'any alphabet',
  },
  ru: {
    'pp.length': 'Не короче {n} символов',
    'pp.digits': 'Не меньше {n} цифр',
    'pp.special': 'Не меньше {n} спецсимволов (! @ # - _ …)',
    'pp.mixed_case': 'Заглавные и строчные буквы',
    'pp.letters': 'Буквы: {letters}',
    'pp.username': 'Не совпадает с логином',
    'pp.control': 'Без управляющих символов',
    'pp.common': 'Не распространённый пароль, не последовательность и не логин с парой символов',
    'pp.history': 'Не совпадает с {n} последними паролями',
    'pp.match': 'Пароли совпадают',
    'pp.letters.latin': 'только латиница',
    'pp.letters.cyrillic': 'только кириллица',
    'pp.letters.latin_cyrillic': 'латиница и кириллица',
    'pp.letters.any': 'любой алфавит',
  },
}

type T = (k: string, v?: Record<string, string | number>) => string

export function ruleText(t: T, rule: Violation, p: PasswordPolicy) {
  const n = { length: p.min_length, digits: p.min_digits, special: p.min_special, history: p.history_count }[rule as 'length'] ?? 0
  return t(`pp.${rule}`, { n, letters: t(`pp.letters.${p.letters}`) })
}
