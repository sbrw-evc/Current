import { checkPassword, defaultPolicy, rules as policyRules, type PasswordPolicy, type Violation } from '../../lib/policy'

// The first administrator's password follows the policy of the Umbrella family; the wizard proposes
// the corporate default (lib/policy.ts) and sends the policy with the setup.
export const DEFAULT_POLICY: PasswordPolicy = defaultPolicy

export type Rule = Violation

export const rules = policyRules

// failed lists the rules a password breaks.
export function failed(password: string, username: string, p: PasswordPolicy): Rule[] {
  return checkPassword(password, username, p)
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
