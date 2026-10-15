import { useState, type FormEvent } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { post, setCsrf } from '../api/client'
import type { Me } from '../api/types'
import { errorText, useT, type Dict } from '../i18n'
import { Banner, Brand, Button, Field, Input, Password, Preferences } from '../ui/ui'
import { EntraLoginButton, EntraSignInError } from './settings/EntraLoginButton'
import { SignInMethods } from './identity/SignInMethods'
import { strings as idStrings } from './identity/strings'

const strings: Dict = {
  en: { 'signin.title': 'Sign in', 'signin.username': 'Username', 'signin.password': 'Password', 'signin.submit': 'Sign in', 'signin.hint': 'The same account as in Umbrella Monitoring (LDAP / AD or local).' },
  ru: { 'signin.title': 'Вход', 'signin.username': 'Логин', 'signin.password': 'Пароль', 'signin.submit': 'Войти', 'signin.hint': 'Та же учётная запись, что в Umbrella Monitoring (LDAP / AD или локальная).' },
}

const loginStrings: Dict = { en: { ...idStrings.en, ...strings.en }, ru: { ...idStrings.ru, ...strings.ru } }

export function LoginPage() {
  const t = useT(loginStrings)
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const qc = useQueryClient()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<{ message: string; detail?: string } | null>(null)

  const done = (me: Me) => {
    setCsrf(me.csrf)
    qc.setQueryData(['me'], me)
    const next = params.get('next')
    navigate(next && next.startsWith('/') && !next.startsWith('//') ? next : '/', { replace: true })
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      done(await post<Me>('/api/auth/login', { username, password }))
    } catch (err) {
      setError(errorText(t, err))
      setPassword('')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="center-page signin-page">
      <div className="card signin">
        <div className="row" style={{ justifyContent: 'space-between' }}>
          <Brand />
          <Preferences />
        </div>
        <form onSubmit={submit} noValidate>
          <h1>{t('signin.title')}</h1>
          {!error && <EntraSignInError />}
          <SignInMethods position="top" onSignedIn={done} />
          {error && (
            <Banner kind="error" title={error.message}>
              {error.detail}
            </Banner>
          )}
          <Field label={t('signin.username')}>{(id) => <Input id={id} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus />}</Field>
          <Field label={t('signin.password')}>{(id) => <Password id={id} value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />}</Field>
          <Button variant="primary" type="submit" busy={busy} disabled={!username || !password}>
            {t('signin.submit')}
          </Button>
          <EntraLoginButton />
          <SignInMethods position="bottom" onSignedIn={done} />
          <p className="hint">{t('signin.hint')}</p>
        </form>
      </div>
    </div>
  )
}
