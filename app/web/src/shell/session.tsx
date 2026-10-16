import { createContext, useContext } from 'react'
import type { User } from '../api/types'

// accountURL is Keystone's page where the person changes their password and passkeys ("Account and security").
export type Session = { user: User; can: (perm: string) => boolean; signOut: () => void; accountURL: string }

const SessionContext = createContext<Session | null>(null)
export const SessionProvider = SessionContext.Provider

export function useSession(): Session {
  const s = useContext(SessionContext)
  if (!s) throw new Error('useSession outside of the session')
  return s
}
