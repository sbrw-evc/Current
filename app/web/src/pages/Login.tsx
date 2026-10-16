import { useEffect, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { LogIn } from 'lucide-react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { get, post } from '../api/client'
import { useT } from '../i18n'
import { Banner, Brand, Button, Loading, Preferences } from '../ui/ui'
import { autoRedirect, safeNext, SPA_PROTOCOL, ssoErrorKey, startURL, takeSignedOut, type SpaInfo } from './keystone/model'
import { spaStrings } from './keystone/strings'

// LoginPage: one button, "Sign in with Keystone" (docs/identity-federation.md). Without a session the
// page goes to Keystone by itself, except right after a sign-out or when Keystone sent an error back
// (/login?sso_error=…). An application not connected to Keystone says so, with the instructions.
export function LoginPage() {
  const t = useT(spaStrings)
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [params] = useSearchParams()
  const next = safeNext(params.get('next'))
  const ssoError = params.get('sso_error')
  const ssoDescription = params.get('sso_error_description')
  // Read once: the mark of a sign-out lasts for one visit of the page.
  const [signedOut] = useState(takeSignedOut)
  const info = useQuery({ queryKey: ['spa-info'], queryFn: ({ signal }) => get<SpaInfo>('/api/auth/spa', signal), retry: 1 })
  const went = useRef(false)

  const go = (prompt?: 'login') => {
    window.location.assign(startURL(next, { prompt }))
  }
  // The mock API (VITE_MOCK=1) signs in without leaving the page.
  const mockSignIn = async () => {
    await post('/api/auth/spa/mock')
    await qc.invalidateQueries({ queryKey: ['me'] })
    navigate(next, { replace: true })
  }

  useEffect(() => {
    if (!went.current && autoRedirect(info.data, ssoError, signedOut)) {
      went.current = true
      window.location.assign(startURL(next))
    }
  }, [info.data, ssoError, signedOut, next])

  const redirecting = autoRedirect(info.data, ssoError, signedOut)
  const redirect = `${window.location.origin}/api/auth/spa/callback`

  return (
    <div className="center-page signin-page">
      <div className="card signin">
        <div className="row" style={{ justifyContent: 'space-between' }}>
          <Brand />
          <Preferences />
        </div>
        <div className="stack">
          <h1>{t('signin.title')}</h1>
          {info.isPending && <Loading />}
          {info.isError && <Banner kind="error" title={t('signin.unavailable')} />}
          {ssoError && (
            <Banner kind="error" title={t(ssoErrorKey(ssoError))}>
              {ssoDescription}
            </Banner>
          )}
          {signedOut && !ssoError && <Banner kind="info" title={t('signin.signedout')} />}
          {info.data && !info.data.connected && (
            <Banner kind="warn" title={t('notconnected.title')}>
              {info.data.error === 'invalid_key' && <p>{t('notconnected.badkey')}</p>}
              <p>{t('notconnected.text')}</p>
              <ol className="spa-steps">
                <li>{t('notconnected.step1', { redirect })}</li>
                <li>{t('notconnected.step2')}</li>
                <li>{t('notconnected.step3')}</li>
              </ol>
              <a href={SPA_PROTOCOL} target="_blank" rel="noreferrer">
                {t('notconnected.docs')}
              </a>
            </Banner>
          )}
          {info.data?.connected && (
            <>
              <p className="muted">{t('signin.lead')}</p>
              {redirecting ? (
                <p className="muted">{t('signin.redirecting')}</p>
              ) : (
                <Button variant="primary" onClick={() => (info.data?.mock ? void mockSignIn() : go())}>
                  <LogIn size={16} /> {ssoError ? t('signin.again') : t('signin.spa')}
                </Button>
              )}
              {(signedOut || ssoError) && !info.data.mock && (
                <Button variant="ghost" onClick={() => go('login')}>
                  {t('signin.other')}
                </Button>
              )}
              {info.data.issuer && <p className="hint">{info.data.application ? `${info.data.application} · ${info.data.issuer}` : info.data.issuer}</p>}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
