import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Fingerprint, Umbrella } from 'lucide-react'
import { get } from '../../api/client'
import type { Me } from '../../api/types'
import { useT } from '../../i18n'
import { passkeysSupported } from '../../lib/webauthn'
import { Banner, Button } from '../../ui/ui'
import { passkeyError, passkeySignIn, ProviderMark } from './components'
import { strings } from './strings'

type Methods = {
  passkeys: boolean
  entra: boolean
  providers: { id: string; title: string }[]
  umbrella: { hub: string; methods: { id: string; title: string }[] } | null
}

// SignInMethods: the passwordless ways of the sign-in page — a passkey, Umbrella single sign-in
// with the hub's methods, Google / Apple / OpenID Connect and Microsoft.
export function SignInMethods({ onSignedIn, position }: { onSignedIn: (me: Me) => void; position: 'top' | 'bottom' }) {
  const t = useT(strings)
  const q = useQuery({ queryKey: ['auth', 'methods'], queryFn: ({ signal }) => get<Methods>('/api/auth/methods', signal), retry: false, staleTime: 60_000 })
  const [busy, setBusy] = useState('')
  const [error, setError] = useState<{ message: string; detail?: string } | null>(null)
  const m = q.data
  if (!m) return null
  const go = (id: string, href: string) => {
    setBusy(id)
    window.location.assign(href)
  }
  if (position === 'top') {
    if (!m.passkeys || !passkeysSupported()) return null
    const passkey = async () => {
      setBusy('passkey')
      setError(null)
      try {
        onSignedIn(await passkeySignIn<Me>())
      } catch (e) {
        setError(passkeyError(t, e))
      } finally {
        setBusy('')
      }
    }
    return (
      <>
        {error && (
          <Banner kind="error" title={error.message}>
            {error.detail}
          </Banner>
        )}
        <Button variant="primary" className="signin-passkey" busy={busy === 'passkey'} onClick={passkey}>
          <Fingerprint size={18} aria-hidden />
          {t('si.passkey')}
        </Button>
        <p className="hint" style={{ textAlign: 'center', marginTop: -6 }}>
          {t('si.passkey.hint')}
        </p>
        <div className="signin-or">{t('si.or')}</div>
      </>
    )
  }
  const hubMethods = (m.umbrella?.methods ?? []).filter((x) => x.id !== 'passkey' || !m.passkeys)
  const buttons = [
    ...(m.umbrella ? [{ id: 'umbrella', title: t('si.umbrella'), href: '/api/auth/umbrella/start', icon: <Umbrella size={16} aria-hidden /> }] : []),
    ...hubMethods
      .filter((x) => x.id !== 'local')
      .map((x) => ({
        id: `umb-${x.id}`,
        title: t('si.with', { name: x.id === 'passkey' ? t('si.hub.passkey') : x.title }),
        href: `/api/auth/umbrella/start?method=${encodeURIComponent(x.id)}`,
        icon: <ProviderMark id={x.id} />,
      })),
    ...m.providers.map((p) => ({ id: p.id, title: t('si.with', { name: p.title }), href: `/api/auth/sso/${p.id}/start`, icon: <ProviderMark id={p.id} /> })),
  ]
  if (buttons.length === 0) return null
  return (
    <>
      <div className="signin-or">{t('si.or')}</div>
      <div className="signin-methods">
        {buttons.map((b) => (
          <Button key={b.id} busy={busy === b.id} disabled={!!busy && busy !== b.id} onClick={() => go(b.id, b.href)}>
            {b.icon}
            {b.title}
          </Button>
        ))}
      </div>
      {m.umbrella && <p className="hint">{t('si.umbrella.hint')}</p>}
    </>
  )
}
