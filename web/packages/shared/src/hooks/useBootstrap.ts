import { useEffect, useState } from 'react'
import { bootstrapApi, type Bootstrap } from '../api/bootstrap'
import { applyDefaultLanguage } from '../i18n'
import { setRuntimeLocalization } from '../utils'

const DEFAULT: Bootstrap = {
  branding: {
    product_name: 'MXID',
    logo_url: '',
    primary_color: '#2563eb',
    login_page_title: '',
    login_footer_html: '',
    custom_css: '',
  },
  login_methods: {
    password: true,
    sms_otp: false,
    email_magic_link: false,
    external_idp_first: false,
  },
  localization: {
    default_language: 'zh-CN',
    default_timezone: 'Asia/Shanghai',
    date_format: '',
  },
}

// Cache the bootstrap response in module scope so a navigation between
// SPA routes doesn't trigger N parallel fetches.
let cached: Bootstrap | null = null
let inflight: Promise<Bootstrap> | null = null

async function fetchOnce(): Promise<Bootstrap> {
  if (cached) return cached
  if (inflight) return inflight
  inflight = bootstrapApi
    .get()
    .then((b) => {
      cached = b
      return b
    })
    .catch(() => DEFAULT)
    .finally(() => {
      inflight = null
    })
  return inflight
}

// applyBranding pushes the live values into document.title + CSS vars +
// favicon so the whole shell reflects the admin's config without a
// per-component dance.
export function applyBranding(b: Bootstrap['branding']) {
  if (b.product_name) {
    document.title = b.product_name
  }
  if (b.primary_color) {
    document.documentElement.style.setProperty('--color-primary', b.primary_color)
  }
  if (b.custom_css) {
    let style = document.getElementById('mxid-branding-css') as HTMLStyleElement | null
    if (!style) {
      style = document.createElement('style')
      style.id = 'mxid-branding-css'
      document.head.appendChild(style)
    }
    style.textContent = b.custom_css
  }
}

// useBootstrap returns the live bootstrap info + applies branding to the
// document on first load. Re-renders only the consuming component when
// the fetch completes, never on subsequent mount because the result is
// cached.
export function useBootstrap(): Bootstrap {
  const [b, setB] = useState<Bootstrap>(cached ?? DEFAULT)
  useEffect(() => {
    let alive = true
    fetchOnce().then((next) => {
      if (!alive) return
      setB(next)
      applyBranding(next.branding)
      applyDefaultLanguage(next.localization.default_language)
      setRuntimeLocalization({
        timezone: next.localization.default_timezone,
        dateFormat: next.localization.date_format,
        language: next.localization.default_language,
      })
    })
    return () => {
      alive = false
    }
  }, [])
  return b
}
