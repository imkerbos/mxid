// i18n bootstrap — wraps i18next + react-i18next. Default language
// resolves in this order:
//   1. localStorage('mxid_lang')   — user override
//   2. browser navigator.language  — auto-detect
//   3. zh-CN                       — hard fallback
//
// The platform-wide default the admin configured via Settings →
// Localization is fetched separately (via useBootstrap) and overrides
// the navigator default ONLY when the user hasn't picked a language
// explicitly.
import i18next from 'i18next'
import LanguageDetector from 'i18next-browser-languagedetector'
import { initReactI18next } from 'react-i18next'

import zhCN from './locales/zh-CN'
import enUS from './locales/en-US'

const LANG_KEY = 'mxid_lang'

export const SUPPORTED_LANGS = ['zh-CN', 'en-US'] as const
export type LangCode = (typeof SUPPORTED_LANGS)[number]

void i18next
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: {
      'zh-CN': { translation: zhCN },
      'en-US': { translation: enUS },
    },
    fallbackLng: 'zh-CN',
    interpolation: { escapeValue: false },
    detection: {
      order: ['localStorage', 'navigator'],
      lookupLocalStorage: LANG_KEY,
      caches: ['localStorage'],
    },
  })

// setLanguage persists the user's pick and switches i18next live.
// Components subscribed via useTranslation re-render automatically.
export function setLanguage(lang: LangCode) {
  localStorage.setItem(LANG_KEY, lang)
  void i18next.changeLanguage(lang)
}

// applyDefaultLanguage is what the bootstrap hook calls after fetching
// the admin-configured locale. It NEVER overrides an explicit user pick
// — once a user manually sets a language we respect it forever.
export function applyDefaultLanguage(lang: string) {
  if (!lang) return
  if (localStorage.getItem(LANG_KEY)) return
  if (!SUPPORTED_LANGS.includes(lang as LangCode)) return
  void i18next.changeLanguage(lang)
}

export { default as i18n } from 'i18next'
export { useTranslation } from 'react-i18next'
