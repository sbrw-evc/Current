import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react'
import { flushSync } from 'react-dom'
import { animate } from 'motion/react'
import { ApiError } from './api/client'
import type { Locale } from './api/types'
import { reducedMotion } from './lib/fx'

// Translations, as in Umbrella: every module keeps a dictionary { en: {...}, ru: {...} } and reads
// it with useT(dict); `common` holds the strings shared by all pages. Russian is the default.
export type Dict = Record<Locale, Record<string, string>>
export type TFunc = (key: string, vars?: Record<string, string | number>) => string

const KEY = 'flow.locale'

export const common: Dict = {
  en: {
    'app.name': 'Umbrella Flow',
    'app.sub': 'Traffic analysis',
    'theme.light': 'Light',
    'theme.dark': 'Dark',
    'theme.toggle': 'Switch theme',
    'lang.en': 'English',
    'lang.ru': 'Русский',
    'lang.toggle': 'Language',
    yes: 'Yes',
    no: 'No',
    loading: 'Loading…',
    retry: 'Retry',
    save: 'Save',
    saved: 'Saved',
    cancel: 'Cancel',
    delete: 'Delete',
    close: 'Close',
    apply: 'Apply',
    search: 'Search',
    none: 'Nothing here yet',
    'ui.show': 'Show',
    'ui.hide': 'Hide',
    'noaccess.title': 'Not enough permissions',
    'noaccess.text': 'Your role does not give access to this page. Ask an administrator.',
    'notfound.title': 'Page not found',
    'err.network': 'The server does not answer. Check the connection and try again.',
    'err.bad_request': 'The request was rejected as invalid.',
    'err.internal': 'Internal server error.',
    'err.invalid_setup_code': 'The setup code is wrong.',
    'err.invalid_filter': 'The filter has errors.',
    'err.unauthenticated': 'Your session has ended. Sign in again.',
    'err.forbidden': 'Not enough permissions.',
    'err.csrf': 'The session token is outdated. Reload the page.',
    'err.not_found': 'Not found.',
    'err.unknown': 'Something went wrong.',
  },
  ru: {
    'app.name': 'Umbrella Flow',
    'app.sub': 'Анализ трафика',
    'theme.light': 'Светлая',
    'theme.dark': 'Тёмная',
    'theme.toggle': 'Сменить тему',
    'lang.en': 'English',
    'lang.ru': 'Русский',
    'lang.toggle': 'Язык',
    yes: 'Да',
    no: 'Нет',
    loading: 'Загрузка…',
    retry: 'Повторить',
    save: 'Сохранить',
    saved: 'Сохранено',
    cancel: 'Отмена',
    delete: 'Удалить',
    close: 'Закрыть',
    apply: 'Применить',
    search: 'Найти',
    none: 'Здесь пока пусто',
    'ui.show': 'Показать',
    'ui.hide': 'Скрыть',
    'noaccess.title': 'Недостаточно прав',
    'noaccess.text': 'Ваша роль не даёт доступа к этой странице. Обратитесь к администратору.',
    'notfound.title': 'Страница не найдена',
    'err.network': 'Сервер не отвечает. Проверьте подключение и повторите.',
    'err.bad_request': 'Запрос отклонён как некорректный.',
    'err.internal': 'Внутренняя ошибка сервера.',
    'err.invalid_setup_code': 'Неверный код установки.',
    'err.invalid_filter': 'В фильтре есть ошибки.',
    'err.unauthenticated': 'Сессия завершилась. Войдите снова.',
    'err.forbidden': 'Недостаточно прав.',
    'err.csrf': 'Токен сессии устарел. Обновите страницу.',
    'err.not_found': 'Не найдено.',
    'err.unknown': 'Что-то пошло не так.',
  },
}

type Ctx = { locale: Locale; setLocale: (l: Locale) => void }

const LocaleContext = createContext<Ctx>({ locale: 'ru', setLocale: () => {} })

export function savedLocale(): Locale | null {
  try {
    const v = localStorage.getItem(KEY)
    return v === 'en' || v === 'ru' ? v : null
  } catch {
    return null
  }
}

export function LocaleProvider({ initial, children }: { initial: Locale; children: ReactNode }) {
  const [locale, set] = useState<Locale>(initial)
  const current = useRef(initial)
  const busy = useRef(false)
  const setLocale = useCallback((l: Locale) => {
    const apply = () => {
      current.current = l
      flushSync(() => set(l))
      document.documentElement.lang = l
    }
    const root = document.getElementById('root')
    if (l === current.current || !root || reducedMotion() || busy.current) {
      apply()
    } else {
      busy.current = true
      animate(root, { opacity: 0, filter: 'blur(3px)' }, { duration: 0.14, ease: 'easeIn' })
        .then(() => {
          apply()
          return animate(root, { opacity: 1, filter: 'blur(0px)' }, { duration: 0.24, ease: [0.22, 1, 0.36, 1] })
        })
        .finally(() => {
          root.style.filter = ''
          busy.current = false
        })
    }
    try {
      localStorage.setItem(KEY, l)
    } catch {
      // The choice then lasts until reload.
    }
  }, [])
  document.documentElement.lang = locale
  return <LocaleContext.Provider value={{ locale, setLocale }}>{children}</LocaleContext.Provider>
}

export function useLocale() {
  return useContext(LocaleContext)
}

export function translate(locale: Locale, extra?: Dict): TFunc {
  const table = { ...common[locale], ...(extra?.[locale] ?? {}) }
  return (key, vars) => {
    let s = table[key] ?? key
    if (vars) for (const [k, v] of Object.entries(vars)) s = s.split(`{${k}}`).join(String(v))
    return s
  }
}

export function useT(extra?: Dict): TFunc {
  const { locale } = useLocale()
  return useMemo(() => translate(locale, extra), [locale, extra])
}

export function errorText(t: TFunc, e: unknown): { message: string; detail?: string } {
  if (e instanceof ApiError) {
    const key = `err.${e.code}`
    const message = t(key)
    return { message: message === key ? t('err.unknown') : message, detail: e.detail }
  }
  return { message: t('err.unknown'), detail: e instanceof Error ? e.message : String(e) }
}
