import { useEffect, useState, type FormEvent } from 'react'
import { motion } from 'framer-motion'
import QRCode from 'qrcode'
import { portalApi, formatDate, cn, parseUserAgent, useTranslation } from '@mxid/shared'
import { Button } from '@mxid/shared/ui'
import { toast } from '@mxid/shared/ui/toast'
import type { MFAInfo, SessionInfo } from '@mxid/shared'
import {
  KeyRound,
  Shield,
  Monitor,
  Loader2,
  AlertCircle,
  CheckCircle,
  Eye,
  EyeOff,
  Trash2,
  Smartphone,
  Copy,
  X,
} from 'lucide-react'

export default function SecurityPage() {
  const { t } = useTranslation()
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      <div className="mb-6">
        <h1 className="text-xl font-semibold text-gray-900">{t('account.title')}</h1>
        <p className="mt-1 text-sm text-gray-500">{t('account.subtitle')}</p>
      </div>

      <div className="space-y-6">
        <ChangePasswordSection />
        <MFASection />
        <SessionsSection />
      </div>
    </motion.div>
  )
}

/* ------------------------------------------------------------------ */
/*  Change Password                                                    */
/* ------------------------------------------------------------------ */
function ChangePasswordSection() {
  const { t } = useTranslation()
  const [oldPwd, setOldPwd] = useState('')
  const [newPwd, setNewPwd] = useState('')
  const [confirmPwd, setConfirmPwd] = useState('')
  const [showOld, setShowOld] = useState(false)
  const [showNew, setShowNew] = useState(false)
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState<{ type: 'ok' | 'err'; text: string } | null>(null)

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    if (saving) return
    if (newPwd !== confirmPwd) {
      setMsg({ type: 'err', text: t('account.pwd.mismatch') })
      return
    }
    if (newPwd.length < 8) {
      setMsg({ type: 'err', text: t('account.pwd.tooShort') })
      return
    }
    setSaving(true)
    setMsg(null)
    try {
      await portalApi.changePassword(oldPwd, newPwd)
      setMsg({ type: 'ok', text: t('common.success') })
      setOldPwd('')
      setNewPwd('')
      setConfirmPwd('')
    } catch (err: unknown) {
      const text = err instanceof Error ? err.message : t('account.pwd.changeFailed')
      setMsg({ type: 'err', text })
    } finally {
      setSaving(false)
    }
  }

  return (
    <SectionCard icon={KeyRound} title={t('account.passwordSection')}>
      <form onSubmit={handleSubmit} className="max-w-md space-y-4">
        {/* Old password */}
        <div>
          <label className="mb-1.5 block text-sm font-medium text-gray-700">
            {t('account.pwd.old')}
          </label>
          <div className="relative">
            <input
              type={showOld ? 'text' : 'password'}
              value={oldPwd}
              onChange={(e) => setOldPwd(e.target.value)}
              placeholder={t('account.pwd.old')}
              autoComplete="current-password"
              className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2.5 pr-10 text-sm text-gray-900 outline-none transition-colors placeholder:text-gray-400 focus:border-primary focus:ring-2 focus:ring-primary/20"
            />
            <button
              type="button"
              onClick={() => setShowOld(!showOld)}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
            >
              {showOld ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
        </div>

        {/* New password */}
        <div>
          <label className="mb-1.5 block text-sm font-medium text-gray-700">
            {t('account.pwd.new')}
          </label>
          <div className="relative">
            <input
              type={showNew ? 'text' : 'password'}
              value={newPwd}
              onChange={(e) => setNewPwd(e.target.value)}
              placeholder={t('account.pwd.new')}
              autoComplete="new-password"
              className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2.5 pr-10 text-sm text-gray-900 outline-none transition-colors placeholder:text-gray-400 focus:border-primary focus:ring-2 focus:ring-primary/20"
            />
            <button
              type="button"
              onClick={() => setShowNew(!showNew)}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
            >
              {showNew ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
        </div>

        {/* Confirm */}
        <div>
          <label className="mb-1.5 block text-sm font-medium text-gray-700">
            {t('account.pwd.confirm')}
          </label>
          <input
            type="password"
            value={confirmPwd}
            onChange={(e) => setConfirmPwd(e.target.value)}
            placeholder={t('account.pwd.confirm')}
            autoComplete="new-password"
            className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2.5 text-sm text-gray-900 outline-none transition-colors placeholder:text-gray-400 focus:border-primary focus:ring-2 focus:ring-primary/20"
          />
        </div>

        {msg && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className={`flex items-center gap-2 rounded-lg px-3 py-2 text-sm ${
              msg.type === 'ok' ? 'bg-emerald-50 text-emerald-600' : 'bg-red-50 text-red-600'
            }`}
          >
            {msg.type === 'ok' ? <CheckCircle className="h-4 w-4" /> : <AlertCircle className="h-4 w-4" />}
            {msg.text}
          </motion.div>
        )}

        <Button type="submit" loading={saving} disabled={saving || !oldPwd || !newPwd || !confirmPwd}>
          {saving ? t('account.pwd.submitting') : t('account.pwd.submit')}
        </Button>
      </form>
    </SectionCard>
  )
}

/* ------------------------------------------------------------------ */
/*  MFA Management                                                     */
/* ------------------------------------------------------------------ */
function MFASection() {
  const { t } = useTranslation()
  const [mfaList, setMfaList] = useState<MFAInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [enrollOpen, setEnrollOpen] = useState(false)

  const fetchMFA = () => {
    setLoading(true)
    portalApi
      .listMFA()
      .then((list) => {
        setMfaList(list)
        setError('')
      })
      .catch((err: Error) => setError(err.message || t('common.failed')))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    fetchMFA()
  }, [])

  const totp = mfaList.find((m) => m.type === 'totp')
  const totpActive = !!totp?.verified

  const handleDisableTOTP = async () => {
    if (!confirm(t('account.mfa.disableConfirm'))) return
    try {
      await portalApi.deleteTOTP()
      toast.success(t('account.mfa.disabled'))
      fetchMFA()
    } catch (err) {
      const msg = err instanceof Error ? err.message : t('common.failed')
      toast.error(t('account.mfa.disableFailed'), msg)
    }
  }

  const mfaTypeLabel = (type: string) => {
    const map: Record<string, string> = {
      totp: t('account.mfa.type.totp'),
      sms: t('account.mfa.type.sms'),
      email: t('account.mfa.type.email'),
    }
    return map[type] || type.toUpperCase()
  }

  return (
    <SectionCard
      icon={Shield}
      title={t('account.mfaSection')}
      action={
        !totpActive ? (
          <Button size="sm" onClick={() => setEnrollOpen(true)}>
            {t('account.mfa.enableTotp')}
          </Button>
        ) : null
      }
    >
      {loading ? (
        <div className="flex items-center gap-2 py-4 text-sm text-gray-500">
          <Loader2 className="h-4 w-4 animate-spin" />
          {t('common.loading')}
        </div>
      ) : error ? (
        <p className="text-sm text-red-500">{error}</p>
      ) : mfaList.length === 0 ? (
        <div className="flex items-center gap-3 rounded-lg border border-dashed border-gray-300 bg-gray-50/50 px-4 py-6 text-sm text-gray-500">
          <Shield className="h-5 w-5 text-gray-400" />
          {t('account.mfa.noFactorAdmin')}
        </div>
      ) : (
        <div className="space-y-3">
          {mfaList.map((mfa) => (
            <div
              key={mfa.type}
              className="flex items-center justify-between rounded-lg border border-gray-200 bg-white px-4 py-3"
            >
              <div className="flex items-center gap-3">
                <Smartphone className="h-5 w-5 text-primary" />
                <div>
                  <p className="text-sm font-medium text-gray-900">
                    {mfaTypeLabel(mfa.type)}
                  </p>
                  <p className="text-xs text-gray-500">
                    {mfa.is_default ? t('account.mfa.defaultMethod') : t('account.mfa.backupMethod')}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span
                  className={cn(
                    'rounded-full px-2.5 py-0.5 text-xs font-medium',
                    mfa.verified
                      ? 'bg-emerald-50 text-emerald-600'
                      : 'bg-amber-50 text-amber-600',
                  )}
                >
                  {mfa.verified ? t('account.fields.verified') : t('account.fields.unverified')}
                </span>
                {mfa.type === 'totp' && mfa.verified && (
                  <button
                    onClick={handleDisableTOTP}
                    className="flex items-center gap-1 rounded-lg px-2.5 py-1 text-xs font-medium text-red-600 transition-colors hover:bg-red-50"
                  >
                    <Trash2 className="h-3.5 w-3.5" /> {t('account.mfa.disable')}
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {enrollOpen && (
        <EnrollTOTPModal
          onClose={() => setEnrollOpen(false)}
          onSuccess={() => {
            setEnrollOpen(false)
            fetchMFA()
          }}
        />
      )}
    </SectionCard>
  )
}

/* ------------------------------------------------------------------ */
/*  TOTP enrollment modal                                              */
/* ------------------------------------------------------------------ */
function EnrollTOTPModal({
  onClose,
  onSuccess,
}: {
  onClose: () => void
  onSuccess: () => void
}) {
  const { t } = useTranslation()
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
          // QR render failed — fall back to manual entry. Not fatal.
        }
      })
      .catch((e: Error) => alive && setErr(e.message || t('common.failed')))
      .finally(() => alive && setLoading(false))
    return () => {
      alive = false
    }
  }, [])

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    if (code.length !== 6) return
    setVerifying(true)
    try {
      await portalApi.verifyTOTP(code)
      toast.success(t('account.mfa.enabled'), t('account.mfa.enabledHint'))
      onSuccess()
    } catch (e) {
      const msg = e instanceof Error ? e.message : t('common.failed')
      toast.error(t('login.invalidCaptcha'), msg)
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

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4"
      onClick={onClose}
    >
      <div
        className="w-full max-w-md rounded-2xl bg-white p-6 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-base font-semibold text-gray-900">{t('account.mfa.enrollTitle')}</h3>
          <button
            onClick={onClose}
            className="rounded-full p-1 text-gray-400 hover:bg-gray-100"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-6 w-6 animate-spin text-primary" />
          </div>
        ) : err ? (
          <p className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-600">{err}</p>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <p className="text-xs text-gray-500">
              {t('account.mfa.enrollHint')}
            </p>
            <div className="flex justify-center rounded-xl border border-gray-200 bg-gray-50 p-3">
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
              <label className="mb-1 block text-xs font-medium text-gray-600">
                {t('account.mfa.secretManual')}
              </label>
              <div className="flex items-center gap-2">
                <input
                  readOnly
                  value={secret}
                  className="flex-1 rounded-lg border border-gray-200 bg-gray-50 px-3 py-2 font-mono text-xs text-gray-700"
                />
                <button
                  type="button"
                  onClick={copySecret}
                  className="rounded-lg border border-gray-200 px-3 py-2 text-xs hover:bg-gray-50"
                  title={t('account.mfa.copyTitle')}
                >
                  <Copy className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-gray-600">
                {t('account.mfa.verifyCode')}
              </label>
              <input
                autoFocus
                inputMode="numeric"
                pattern="[0-9]*"
                maxLength={6}
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-center text-lg font-mono tracking-widest text-gray-900 outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                placeholder="••••••"
              />
            </div>
            <div className="flex justify-end gap-2 pt-1">
              <button
                type="button"
                onClick={onClose}
                className="rounded-lg border border-gray-200 px-4 py-2 text-sm hover:bg-gray-50"
              >
                {t('common.cancel')}
              </button>
              <button
                type="submit"
                disabled={code.length !== 6 || verifying}
                className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-white hover:bg-primary-hover disabled:cursor-not-allowed disabled:opacity-50"
              >
                {verifying && <Loader2 className="h-4 w-4 animate-spin" />}
                {t('account.mfa.submit')}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/*  Active Sessions                                                    */
/* ------------------------------------------------------------------ */
function SessionsSection() {
  const { t } = useTranslation()
  const [sessions, setSessions] = useState<SessionInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [revoking, setRevoking] = useState<string | null>(null)

  const fetchSessions = () => {
    setLoading(true)
    portalApi
      .listSessions()
      .then(setSessions)
      .catch((err: Error) => setError(err.message || t('account.sessions.loadError')))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    fetchSessions()
  }, [])

  const handleRevoke = async (sid: string) => {
    if (revoking) return
    setRevoking(sid)
    try {
      await portalApi.deleteSession(sid)
      setSessions((prev) => prev.filter((s) => s.id !== sid))
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : t('account.sessions.kickFailed')
      toast.error(t('account.sessions.kickFailed'), msg)
    } finally {
      setRevoking(null)
    }
  }

  // UA parsing — delegated to shared util (ua-parser-js) so console reuses
  // the same logic. Returns "Chrome 149 · macOS 15.2"-style strings.
  const parseUA = (ua: string) => parseUserAgent(ua).short

  return (
    <SectionCard icon={Monitor} title={t('account.sessions.title')}>
      {loading ? (
        <div className="flex items-center gap-2 py-4 text-sm text-gray-500">
          <Loader2 className="h-4 w-4 animate-spin" />
          {t('common.loading')}
        </div>
      ) : error ? (
        <p className="text-sm text-red-500">{error}</p>
      ) : sessions.length === 0 ? (
        <p className="py-4 text-sm text-gray-500">{t('account.sessions.empty')}</p>
      ) : (
        <div className="space-y-3">
          {sessions.map((session) => (
            <div
              key={session.id}
              className="flex items-center justify-between rounded-lg border border-gray-200 bg-white px-4 py-3"
            >
              <div className="flex items-center gap-3">
                <Monitor className="h-5 w-5 text-gray-400" />
                <div>
                  <p className="text-sm font-medium text-gray-900">
                    {parseUA(session.user_agent)}
                  </p>
                  <p className="text-xs text-gray-500">
                    IP: {session.ip} &middot; {t('account.sessions.lastActiveLabel')}: {formatDate(session.last_active_at)}
                  </p>
                </div>
              </div>
              <button
                onClick={() => handleRevoke(session.id)}
                disabled={revoking === session.id}
                className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium text-red-600 transition-colors hover:bg-red-50 disabled:opacity-50"
              >
                {revoking === session.id ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Trash2 className="h-3.5 w-3.5" />
                )}
                {t('account.sessions.kick')}
              </button>
            </div>
          ))}
        </div>
      )}
    </SectionCard>
  )
}

/* ------------------------------------------------------------------ */
/*  Shared Section Card                                                */
/* ------------------------------------------------------------------ */
function SectionCard({
  icon: Icon,
  title,
  action,
  children,
}: {
  icon: React.ComponentType<{ className?: string }>
  title: string
  action?: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <div className="rounded-xl border border-gray-200 bg-white p-6">
      <div className="mb-4 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Icon className="h-5 w-5 text-primary" />
          <h2 className="text-base font-semibold text-gray-900">{title}</h2>
        </div>
        {action}
      </div>
      {children}
    </div>
  )
}
