import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { motion } from 'framer-motion'
import { CheckCircle2, Loader2, ShieldQuestion, XCircle } from 'lucide-react'
import { portalApi, useTranslation } from '@mxid/shared'

interface ConsentApp {
  id: string
  name: string
  description: string
  logo_url: string
  home_url: string
}

interface ScopeItem {
  scope: string
  label: string
}

// Consent screen — OIDC Core 1.0 §3.1.2.4.
//
// User arrives via redirect from /protocol/oidc/authorize when the app
// requires consent and a matching grant does not yet exist. After 同意,
// posts to /api/v1/portal/consent and navigates back to `return_to`
// (the original authorize URL) so the IdP can resume the flow.
//
// 拒绝 cancels the OIDC flow per spec (returns the user to the RP with
// error=access_denied — handled here by sending the user home).
export default function ConsentPage() {
  const { t } = useTranslation()
  const [params] = useSearchParams()
  const appId = params.get('app_id') || ''
  const scopeQ = params.get('scope') || ''
  const returnTo = params.get('return_to') || '/apps'
  const scopes = scopeQ.split(/[\s+]+/).filter(Boolean)

  const [loading, setLoading] = useState(true)
  const [app, setApp] = useState<ConsentApp | null>(null)
  const [scopeItems, setScopeItems] = useState<ScopeItem[]>([])
  const [submitting, setSubmitting] = useState<'allow' | 'deny' | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!appId || scopes.length === 0) {
      setError(t('common.error'))
      setLoading(false)
      return
    }
    portalApi
      .consentPreview(appId, scopes)
      .then((data) => {
        setApp(data.app)
        setScopeItems(data.scopes || [])
      })
      .catch((err: Error) => setError(err.message || t('common.failed')))
      .finally(() => setLoading(false))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [appId, scopeQ])

  const handleAllow = async () => {
    if (submitting) return
    setSubmitting('allow')
    try {
      await portalApi.grantConsent(appId, scopes)
      window.location.href = returnTo
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : t('common.failed')
      setError(msg)
      setSubmitting(null)
    }
  }

  const handleDeny = () => {
    setSubmitting('deny')
    // 用户拒绝 — 取消 OIDC 流程, 回应用库 (规范: RP 会从 authorize 收到 access_denied)
    window.location.href = '/apps'
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-32">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    )
  }

  if (error || !app) {
    return (
      <div className="mx-auto max-w-md py-24 text-center">
        <XCircle className="mx-auto h-12 w-12 text-red-400" />
        <p className="mt-3 text-sm text-gray-600">{error || t('common.empty')}</p>
      </div>
    )
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="mx-auto max-w-lg"
    >
      <div className="rounded-2xl border border-gray-200 bg-white p-8 shadow-sm">
        <div className="mb-6 flex items-center gap-4">
          <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-xl bg-primary/10 text-primary">
            {app.logo_url ? (
              <img src={app.logo_url} alt={app.name} className="h-9 w-9 rounded-md object-cover" />
            ) : (
              <ShieldQuestion className="h-7 w-7" />
            )}
          </div>
          <div className="min-w-0">
            <h1 className="text-lg font-semibold text-gray-900">{app.name}</h1>
            <p className="mt-0.5 text-xs text-gray-500">{app.description || t('portal.consent.subtitle')}</p>
          </div>
        </div>

        <p className="mb-3 text-sm font-medium text-gray-700">{t('portal.consent.subtitle')}</p>
        <ul className="mb-8 space-y-2">
          {scopeItems.map((s) => (
            <li
              key={s.scope}
              className="flex items-start gap-3 rounded-lg border border-gray-100 bg-gray-50 px-3 py-2.5"
            >
              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
              <div className="min-w-0">
                <p className="text-sm text-gray-800">{s.label}</p>
                <p className="font-mono text-[10px] text-gray-400">{s.scope}</p>
              </div>
            </li>
          ))}
        </ul>

        <div className="flex gap-3">
          <button
            type="button"
            onClick={handleDeny}
            disabled={!!submitting}
            className="flex-1 rounded-lg border border-gray-300 px-4 py-2.5 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-50 disabled:opacity-50"
          >
            {t('portal.consent.denyBtn')}
          </button>
          <button
            type="button"
            onClick={handleAllow}
            disabled={!!submitting}
            className="flex flex-1 items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-primary-hover disabled:opacity-60"
          >
            {submitting === 'allow' && <Loader2 className="h-4 w-4 animate-spin" />}
            {t('portal.consent.grantBtn')}
          </button>
        </div>
      </div>

      <p className="mt-4 text-center text-xs text-gray-400">
        {app.name}
      </p>
    </motion.div>
  )
}
