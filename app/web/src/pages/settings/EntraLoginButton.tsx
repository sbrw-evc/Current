import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { get } from '../../api/client'
import { useT, type Dict } from '../../i18n'
import { Banner } from '../../ui/ui'
import { SIGNIN_ERRORS } from './EntraModel'

// The "Sign in with Microsoft" button of the sign-in page (shown when Entra ID sign-in is on) and the
// error the Entra callback left in ?signin_error=…

const strings: Dict = {
  en: {
    'entra.button': 'Sign in with Microsoft',
    'entra.or': 'or',
    'entra.err.entra_off': 'Sign-in with Microsoft is turned off.',
    'entra.err.entra_unavailable': 'Microsoft Entra ID is not available. Try again later.',
    'entra.err.entra_denied': 'Microsoft did not let the sign-in through.',
    'entra.err.entra_state': 'The sign-in has expired or was started in another browser. Try again.',
    'entra.err.entra_account': 'The Microsoft account has no usable user name.',
    'entra.err.entra_no_role': 'Your Entra ID groups give no role in Flow. Ask an administrator.',
    'entra.err.entra_conflict': 'A local or LDAP user with this name already exists.',
    'entra.err.user_disabled': 'The account is disabled.',
    'entra.err.too_many_attempts': 'Too many sign-in attempts. Try again in a minute.',
    'entra.err.unknown': 'Sign-in with Microsoft failed.',
  },
  ru: {
    'entra.button': 'Войти через Microsoft',
    'entra.or': 'или',
    'entra.err.entra_off': 'Вход через Microsoft выключен.',
    'entra.err.entra_unavailable': 'Microsoft Entra ID недоступен. Попробуйте позже.',
    'entra.err.entra_denied': 'Microsoft не разрешил вход.',
    'entra.err.entra_state': 'Вход устарел или был начат в другом браузере. Попробуйте ещё раз.',
    'entra.err.entra_account': 'У учётной записи Microsoft нет подходящего имени пользователя.',
    'entra.err.entra_no_role': 'Ваши группы Entra ID не дают роли во Flow. Обратитесь к администратору.',
    'entra.err.entra_conflict': 'Локальный или LDAP-пользователь с таким именем уже есть.',
    'entra.err.user_disabled': 'Учётная запись заблокирована.',
    'entra.err.too_many_attempts': 'Слишком много попыток входа. Повторите через минуту.',
    'entra.err.unknown': 'Войти через Microsoft не удалось.',
  },
}

const KNOWN = new Set<string>(SIGNIN_ERRORS)

function MicrosoftLogo() {
  return (
    <svg width="16" height="16" viewBox="0 0 21 21" aria-hidden>
      <rect x="1" y="1" width="9" height="9" fill="#f25022" />
      <rect x="11" y="1" width="9" height="9" fill="#7fba00" />
      <rect x="1" y="11" width="9" height="9" fill="#00a4ef" />
      <rect x="11" y="11" width="9" height="9" fill="#ffb900" />
    </svg>
  )
}

export function EntraSignInError() {
  const t = useT(strings)
  const [params] = useSearchParams()
  const code = params.get('signin_error')
  if (!code) return null
  return <Banner kind="error" title={t(KNOWN.has(code) ? `entra.err.${code}` : 'entra.err.unknown')} />
}

export function EntraLoginButton() {
  const t = useT(strings)
  const q = useQuery({ queryKey: ['auth', 'entra'], queryFn: ({ signal }) => get<{ enabled: boolean }>('/api/auth/entra', signal), retry: false, staleTime: 60_000 })
  if (!q.data?.enabled) return null
  return (
    <>
      <div className="hint" style={{ textAlign: 'center' }}>
        {t('entra.or')}
      </div>
      {/* A plain link: the browser goes to Microsoft and comes back through the callback. */}
      <a className="btn btn-secondary" href="/api/auth/entra/start">
        <MicrosoftLogo />
        {t('entra.button')}
      </a>
    </>
  )
}
