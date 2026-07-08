import { useEffect, useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import QRCode from 'qrcode'
import { ShieldCheck, Loader2, Copy, LogOut } from 'lucide-react'
import { portalApi, authApi, useAuthStore, useTranslation } from '@mxid/shared'
import { toast } from '@mxid/shared/ui/toast'

/**
 * ForceMfaEnroll — full-screen blocking gate shown when the backend enroll gate
 * reports the tenant's MFA policy requires this user to hold a factor and they
 * have none (HTTP 403, code 40331). Until they bind TOTP, every other portal
 * route/API would 403, so we render ONLY this — no half-broken pages.
 *
 * On success the server-side session's pending flag self-heals (the EnrollGate
 * middleware clears it once a factor exists), so we drop the client flag and
 * bounce to /apps.
 */
export default function ForceMfaEnroll() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const setMfaEnrollRequired = useAuthStore((s) => s.setMfaEnrollRequired)
  const clear = useAuthStore((s) => s.clear)

  const [secret, setSecret] = useState('')
  const [qrDataURL, setQrDataURL] = useState('')
  const [qrUrl, setQrUrl] = useState('')
  const [code, setCode] = useState('')
  const [loading, setLoading] = useState(true)
  const [verifying, setVerifying] = useState(false)
  const [err, setErr] = useState('')

  useEffect(() => {
    let alive = true
    portalApi
      .setupTOTP()
      .then(async ({ secret, qr_url }) => {
        if (!alive) return
        setSecret(secret)
        setQrUrl(qr_url)
        try {
          const png = await QRCode.toDataURL(qr_url, { width: 220, margin: 1 })
          if (alive) setQrDataURL(png)
        } catch {
          // QR render failed — manual entry still works.
        }
      })
      .catch((e: Error) => alive && setErr(e.message || t('common.failed')))
      .finally(() => alive && setLoading(false))
    return () => {
      alive = false
    }
  }, [t])

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    if (code.length !== 6) return
    setVerifying(true)
    try {
      await portalApi.verifyTOTP(code)
      toast.success(t('account.mfa.enabled'), t('account.mfa.enabledHint'))
      setMfaEnrollRequired(false)
      navigate('/apps', { replace: true })
    } catch (e) {
      const msg = e instanceof Error ? e.message : t('common.failed')
      toast.error(t('account.mfa.verifyFailed'), msg)
    } finally {
      setVerifying(false)
    }
  }

  const copySecret = () => {
    navigator.clipboard
      .writeText(secret)
      .then(() => toast.success(t('account.mfa.copySuccess'), t('account.mfa.copyHint')))
      .catch(() => toast.error(t('account.mfa.copyFail')))
  }

  const logout = () => {
    // Best-effort server logout; clear locally + bounce regardless (the escape
    // hatch must work even if the call fails).
    authApi.portalLogout().catch(() => {})
    clear()
    navigate('/login', { replace: true })
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-canvas p-4">
      <div className="w-full max-w-md rounded-2xl border border-border bg-surface p-6 shadow-xl">
        <div className="mb-4 flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10 text-primary">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-ink">{t('account.mfa.forceTitle')}</h1>
            <p className="text-sm text-muted">{t('account.mfa.forceSubtitle')}</p>
          </div>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-6 w-6 animate-spin text-primary" />
          </div>
        ) : err ? (
          <p className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-600">{err}</p>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <p className="text-xs text-muted">{t('account.mfa.enrollHint')}</p>
            <div className="flex justify-center rounded-xl border border-border bg-surface-muted p-3">
              {qrDataURL ? (
                <img src={qrDataURL} alt="TOTP QR" className="h-44 w-44" />
              ) : (
                <a
                  href={qrUrl}
                  className="break-all text-xs text-primary underline"
                  target="_blank"
                  rel="noreferrer noopener"
                >
                  {qrUrl}
                </a>
              )}
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-muted">
                {t('account.mfa.secretManual')}
              </label>
              <div className="flex items-center gap-2">
                <input
                  readOnly
                  value={secret}
                  className="flex-1 rounded-lg border border-border bg-surface-muted px-3 py-2 font-mono text-xs text-ink"
                />
                <button
                  type="button"
                  onClick={copySecret}
                  className="rounded-lg border border-border px-3 py-2 text-xs hover:bg-surface-muted"
                  title={t('account.mfa.copyTitle')}
                >
                  <Copy className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-muted">
                {t('account.mfa.verifyCode')}
              </label>
              <input
                autoFocus
                inputMode="numeric"
                pattern="[0-9]*"
                maxLength={6}
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                placeholder="000000"
                className="w-full rounded-lg border border-border px-3 py-2 text-center font-mono text-lg tracking-[0.3em] text-ink outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
              />
            </div>
            <button
              type="submit"
              disabled={verifying || code.length !== 6}
              className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-60"
            >
              {verifying && <Loader2 className="h-4 w-4 animate-spin" />}
              {t('account.mfa.forceEnableBtn')}
            </button>
          </form>
        )}

        <button
          onClick={logout}
          className="mt-4 inline-flex w-full items-center justify-center gap-1.5 text-xs text-faint hover:text-ink"
        >
          <LogOut className="h-3.5 w-3.5" />
          {t('nav.logout')}
        </button>
      </div>
    </div>
  )
}
