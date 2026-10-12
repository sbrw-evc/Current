import { createContext, useContext } from 'react'
import type { User } from '../api/types'

export type Session = { user: User; can: (perm: string) => boolean; signOut: () => void }

const SessionContext = createContext<Session | null>(null)
export const SessionProvider = SessionContext.Provider

export function useSession(): Session {
  const s = useContext(SessionContext)
  if (!s) throw new Error('useSession outside of the session')
  return s
}
