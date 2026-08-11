import { useEffect, useState, type FormEvent } from 'react'
import { motion } from 'framer-motion'
import QRCode from 'qrcode'
import { portalApi, externalIdpApi, formatDate, cn, parseUserAgent, useTranslation } from '@mxid/shared'
import { Field, Button, ConfirmDialog } from '@mxid/shared/ui'
import { toast, extractMessage } from '@mxid/shared/ui/toast'
import type { MFAInfo, SessionInfo, FormFillExtToken, IdentityInfo, PublicIDP } from '@mxid/shared'
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
  Puzzle,
  Link2,
} from 'lucide-react'
import { externalAuthReasonKey } from '../../lib/externalAuthReason'

// Reason SLUGS the OAuth-bind round-trip can bounce back with (never raw
// error text — see externalAuthReason.ts's doc comment for why that
// distinction is load-bearing). bind_session_mismatch and bind_unconfigured
// are this flow's own fixed guard slugs (mxid-ee's finishBind, unrelated to
// the shared conflict taxonomy externalAuthReasonKey knows about); anything
// else — the backend's own generic slug, or a value this build predates —
// gets one sensible, actionable sentence: binding failed, retry or contact
// an administrator.
function bindFailureDetail(reason: string, t: (key: string) => string): string | undefined {
  if (reason === 'bind_session_mismatch') return t('account.identities.bindSessionMismatch')
  if (reason === 'bind_unconfigured') return undefined
  const key = externalAuthReasonKey(reason)
  return t(key ?? 'account.identities.bindGenericFailed')
}

export default function SecurityPage() {
  const { t } = useTranslation()

  // The bind round-trip is a full page navigation (the browser leaves for the
  // IdP and comes back), so there is no in-app moment to toast success from —
  // read it once off the URL on mount instead. Success lands here as
  // ?bind=ok (see startBind's finalURL). A failure never reaches this page
  // today (see RedirectIfAuth in App.tsx, which forwards it here as
  // ?bindErr=<reason> so it isn't silently dropped) — handle both under the
  // same effect so a refresh never re-shows either toast.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    let changed = false
    if (params.get('bind') === 'ok') {
      toast.success(t('account.identities.bindSuccess'))
      params.delete('bind')
      changed = true
    }
    const bindErr = params.get('bindErr')
    if (bindErr !== null) {
      toast.error(t('account.identities.bindFailed'), bindFailureDetail(bindErr, t))
      params.delete('bindErr')
      changed = true
    }
    if (changed) {
      const qs = params.toString()
      window.history.replaceState({}, '', window.location.pathname + (qs ? `?${qs}` : ''))
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      <div className="mb-6">
        <h1 className="text-xl font-semibold text-ink">{t('account.title')}</h1>
        <p className="mt-1 text-sm text-muted">{t('account.subtitle')}</p>
      </div>

      <div className="space-y-6">
        <ChangePasswordSection />
        <MFASection />
        <IdentitiesSection />
        <SessionsSection />
        <ConnectedExtensionsSection />
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
  const [totpCode, setTotpCode] = useState('')
  const [showOld, setShowOld] = useState(false)
  const [showNew, setShowNew] = useState(false)
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState<{ type: 'ok' | 'err'; text: string } | null>(null)
  // The backend requires a fresh TOTP code to rotate the password when the user
  // has a verified TOTP factor (step-up: a stolen session cookie alone must not
  // change the credential). Detect it so we can collect the code up front instead
  // of failing the submit with an opaque 400.
  const [totpActive, setTotpActive] = useState(false)
  // false for external-IdP (Lark) accounts that never set a local password. In
  // that mode we drop the old-password field and switch to the "set password"
  // endpoint so the user can gain username+password login alongside Lark.
  // Default true so an existing-password user never briefly sees the set form.
  const [hasPassword, setHasPassword] = useState(true)

  useEffect(() => {
    let alive = true
    portalApi
      .listMFA()
      .then((list) => {
        if (alive) setTotpActive(list.some((m) => m.type === 'totp' && m.verified))
      })
      .catch(() => {
        /* non-fatal: fall back to no-TOTP form; backend still enforces */
      })
    portalApi
      .getProfile()
      .then((p) => {
        if (alive) setHasPassword(p.user.has_password)
      })
      .catch(() => {
        /* non-fatal: keep the change-password form; backend still enforces */
      })
    return () => {
      alive = false
    }
  }, [])

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
    // TOTP step-up only applies when rotating an existing password.
    if (hasPassword && totpActive && !totpCode) {
      setMsg({ type: 'err', text: t('account.pwd.needMfa') })
      return
    }
    setSaving(true)
    setMsg(null)
    try {
      if (hasPassword) {
        await portalApi.changePassword(oldPwd, newPwd, totpActive ? totpCode : undefined)
      } else {
        await portalApi.setPassword(newPwd)
        // Now that a local password exists, switch the form to change-mode.
        setHasPassword(true)
      }
      setMsg({ type: 'ok', text: t('common.success') })
      setOldPwd('')
      setNewPwd('')
      setConfirmPwd('')
      setTotpCode('')
    } catch (err: unknown) {
      setMsg({ type: 'err', text: extractMessage(err, t('account.pwd.changeFailed')) })
    } finally {
      setSaving(false)
    }
  }

  return (
    <SectionCard icon={KeyRound} title={t('account.passwordSection')}>
      <form onSubmit={handleSubmit} className="max-w-md space-y-4">
        {/* Set-password hint for external-IdP accounts with no local password. */}
        {!hasPassword && (
          <p className="rounded-lg bg-primary/5 px-3 py-2 text-xs text-muted">
            {t('account.pwd.setHint')}
          </p>
        )}

        {/* Old password — only when a local password already exists. */}
        {hasPassword && (
          <Field label={t('account.pwd.old')}>
            <div className="relative">
              <input
                type={showOld ? 'text' : 'password'}
                value={oldPwd}
                onChange={(e) => setOldPwd(e.target.value)}
                placeholder={t('account.pwd.old')}
                autoComplete="current-password"
                className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 pr-10 text-sm text-ink outline-none transition-colors placeholder:text-faint focus:border-primary focus:ring-2 focus:ring-primary/20"
              />
              <button
                type="button"
                onClick={() => setShowOld(!showOld)}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-faint hover:text-muted"
              >
                {showOld ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </Field>
        )}

        {/* New password */}
        <Field label={t('account.pwd.new')}>
          <div className="relative">
            <input
              type={showNew ? 'text' : 'password'}
              value={newPwd}
              onChange={(e) => setNewPwd(e.target.value)}
              placeholder={t('account.pwd.new')}
              autoComplete="new-password"
              className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 pr-10 text-sm text-ink outline-none transition-colors placeholder:text-faint focus:border-primary focus:ring-2 focus:ring-primary/20"
            />
            <button
              type="button"
              onClick={() => setShowNew(!showNew)}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-faint hover:text-muted"
            >
              {showNew ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
        </Field>

        {/* Confirm */}
        <Field label={t('account.pwd.confirm')}>
          <input
            type="password"
            value={confirmPwd}
            onChange={(e) => setConfirmPwd(e.target.value)}
            placeholder={t('account.pwd.confirm')}
            autoComplete="new-password"
            className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm text-ink outline-none transition-colors placeholder:text-faint focus:border-primary focus:ring-2 focus:ring-primary/20"
          />
        </Field>

        {/* TOTP step-up: only when rotating an existing password. */}
        {hasPassword && totpActive && (
          <Field label={t('account.pwd.mfaCode')}>
            <input
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              placeholder="123456"
              className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm tracking-widest text-ink outline-none transition-colors placeholder:text-faint placeholder:tracking-normal focus:border-primary focus:ring-2 focus:ring-primary/20"
            />
            <p className="mt-1 text-xs text-muted">{t('account.pwd.mfaCodeHint')}</p>
          </Field>
        )}

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

        <Button
          type="submit"
          loading={saving}
          disabled={
            saving ||
            (hasPassword && !oldPwd) ||
            !newPwd ||
            !confirmPwd ||
            (hasPassword && totpActive && totpCode.length < 6)
          }
        >
          {saving
            ? t('account.pwd.submitting')
            : hasPassword
              ? t('account.pwd.submit')
              : t('account.pwd.setSubmit')}
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
  const [showDisable, setShowDisable] = useState(false)
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
    setShowDisable(false)
    try {
      await portalApi.deleteTOTP()
      toast.success(t('account.mfa.disabled'))
      fetchMFA()
    } catch (err) {
      const msg = extractMessage(err, t('common.failed'))
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
        <div className="flex items-center gap-2 py-4 text-sm text-muted">
          <Loader2 className="h-4 w-4 animate-spin" />
          {t('common.loading')}
        </div>
      ) : error ? (
        <p className="text-sm text-red-500">{error}</p>
      ) : mfaList.length === 0 ? (
        <div className="flex items-center gap-3 rounded-lg border border-dashed border-border bg-surface-muted/50 px-4 py-6 text-sm text-muted">
          <Shield className="h-5 w-5 text-faint" />
          {t('account.mfa.noFactorAdmin')}
        </div>
      ) : (
        <div className="space-y-3">
          {mfaList.map((mfa) => (
            <div
              key={mfa.type}
              className="flex items-center justify-between rounded-lg border border-border bg-surface px-4 py-3"
            >
              <div className="flex items-center gap-3">
                <Smartphone className="h-5 w-5 text-primary" />
                <div>
                  <p className="text-sm font-medium text-ink">
                    {mfaTypeLabel(mfa.type)}
                  </p>
                  <p className="text-xs text-muted">
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
                    onClick={() => setShowDisable(true)}
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

      <ConfirmDialog
        open={showDisable}
        title={t('account.mfa.disableConfirm')}
        onConfirm={handleDisableTOTP}
        onCancel={() => setShowDisable(false)}
      />
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
      const msg = extractMessage(e, t('common.failed'))
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
        className="w-full max-w-md rounded-2xl bg-surface p-6 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-base font-semibold text-ink">{t('account.mfa.enrollTitle')}</h3>
          <button
            onClick={onClose}
            className="rounded-full p-1 text-faint hover:bg-surface-muted"
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
            <p className="text-xs text-muted">
              {t('account.mfa.enrollHint')}
            </p>
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
                className="w-full rounded-lg border border-border px-3 py-2 text-center text-lg font-mono tracking-widest text-ink outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                placeholder="••••••"
              />
            </div>
            <div className="flex justify-end gap-2 pt-1">
              <button
                type="button"
                onClick={onClose}
                className="rounded-lg border border-border px-4 py-2 text-sm hover:bg-surface-muted"
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
/*  Identity bindings (external IdPs)                                  */
/* ------------------------------------------------------------------ */
// Lets a user bind an external-IdP account (e.g. Lark) to their own profile,
// and shows what is already bound. This is the self-service recovery path
// for a binding an administrator removed: completing the IdP's own sign-in
// proves the caller holds the account, so no one else can graft a colleague's
// external identity onto their own profile by typing an id.
//
// The IdP list is externalIdpApi.listPublic() — the same endpoint the login
// page already uses to render its "sign in with ..." buttons — there is no
// separate portal-only list to fetch. A bound identity's provider_id is the
// IdP's `code` (see mxid-ee/features/externalidp/provider.go), which is what
// correlates the two lists.
function IdentitiesSection() {
  const { t } = useTranslation()
  const [identities, setIdentities] = useState<IdentityInfo[]>([])
  const [idps, setIdps] = useState<PublicIDP[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [binding, setBinding] = useState<string | null>(null)

  const fetchAll = () => {
    setLoading(true)
    // The two calls are settled INDEPENDENTLY, because only one of them exists
    // in every edition.
    //
    // externalIdpApi.listPublic() is EE-only — the route is registered in
    // mxid-ee/features/externalidp/register.go and nowhere in CE, so on CE it
    // 404s into the router's NoRoute and the interceptor rejects. Folded into a
    // shared Promise.all that rejection also discarded the identities that HAD
    // loaded, and left `error` set, which the hide-when-empty guard below
    // deliberately refuses to fire through — so every CE portal rendered a
    // permanent red "Identity bindings — <error>" card. A missing or failing
    // IdP list is not an outage; it means "no providers to offer", which is
    // what the login page's own listPublic() swallow already assumes.
    //
    // portalApi.listIdentities() is served by CE (internal/gateway/portal), so
    // a failure there IS a real outage and must stay visible: rendering "no
    // bindings" over a backend that never answered is the same lie this branch
    // exists to remove. That rejection is the only one that reaches setError.
    const idpList = externalIdpApi.listPublic().catch(() => [] as PublicIDP[])
    Promise.all([portalApi.listIdentities(), idpList])
      .then(([ids, list]) => {
        setIdentities(ids)
        setIdps(list)
        setError('')
      })
      .catch((err: Error) => {
        setIdentities([])
        setIdps([])
        setError(err.message || t('common.failed'))
      })
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    fetchAll()
  }, [])

  const boundCodes = new Set(identities.map((i) => i.provider_id))
  const unboundIdps = idps.filter((idp) => !boundCodes.has(idp.code))
  const idpNameByCode = new Map(idps.map((idp) => [idp.code, idp.name]))

  const handleBind = async (idpCode: string) => {
    setBinding(idpCode)
    try {
      const res = await portalApi.startIdentityBind(idpCode)
      // Full-page navigation to the IdP — there is no XHR response to react
      // to next; the OAuth round-trip finishes on ?bind=ok (see the mount
      // effect above). A 403/step_up_required here is handled transparently
      // by the shared axios client (registered by portal's StepUpModal): it
      // runs the step-up prompt and replays this same POST once verified.
      window.location.assign(res.authorize_url)
    } catch (e) {
      toast.error(t('account.identities.bindFailed'), extractMessage(e))
      setBinding(null)
    }
  }

  // Nothing bound and no external IdP configured (CE, or EE with none set
  // up yet) — the whole section would be an empty shell, so skip it, same
  // as the login page's ExternalIdpButtons hiding itself for an empty list.
  // Never on a fetch failure, though: that would show a confident "nothing
  // to bind here" for what is actually a backend outage — the frontend
  // stating something the backend never said. Only listIdentities() can set
  // `error` now (see fetchAll), so this guard reacts to a real outage and no
  // longer to CE simply not serving the EE IdP list.
  if (!loading && !error && idps.length === 0 && identities.length === 0) return null

  return (
    <SectionCard icon={Link2} title={t('account.identities.title')}>
      <p className="mb-3 text-xs text-muted">{t('account.identities.hint')}</p>
      {loading ? (
        <div className="flex items-center gap-2 py-4 text-sm text-muted">
          <Loader2 className="h-4 w-4 animate-spin" />
          {t('common.loading')}
        </div>
      ) : error ? (
        <p className="text-sm text-red-500">{error}</p>
      ) : (
        <div className="space-y-3">
          {identities.map((id) => (
            <div
              key={`${id.provider_type}:${id.provider_id}`}
              className="flex items-center justify-between rounded-lg border border-border bg-surface px-4 py-3"
            >
              <div className="flex items-center gap-3">
                <Link2 className="h-5 w-5 text-primary" />
                <div>
                  <p className="text-sm font-medium text-ink">
                    {id.external_name || idpNameByCode.get(id.provider_id) || id.provider_type}
                  </p>
                  <p className="text-xs text-muted">{idpNameByCode.get(id.provider_id) || id.provider_type}</p>
                </div>
              </div>
              <span className="rounded-full bg-emerald-50 px-2.5 py-0.5 text-xs font-medium text-emerald-600">
                {t('account.identities.bound')}
              </span>
            </div>
          ))}
          {unboundIdps.map((idp) => (
            <div
              key={idp.id}
              className="flex items-center justify-between rounded-lg border border-dashed border-border bg-surface-muted/40 px-4 py-3"
            >
              <div className="flex items-center gap-3">
                {idp.icon ? (
                  <img src={idp.icon} alt="" className="h-5 w-5 rounded object-contain" />
                ) : (
                  <Link2 className="h-5 w-5 text-faint" />
                )}
                <p className="text-sm font-medium text-ink">{idp.name}</p>
              </div>
              <Button
                size="sm"
                variant="secondary"
                loading={binding === idp.code}
                onClick={() => handleBind(idp.code)}
              >
                {t('account.identities.bind')}
              </Button>
            </div>
          ))}
          {identities.length === 0 && unboundIdps.length === 0 && (
            <p className="py-4 text-sm text-muted">{t('account.identities.empty')}</p>
          )}
        </div>
      )}
    </SectionCard>
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

  // Killing a live session is destructive and was one click away. The console
  // already gates the same operation; this brings the portal in line.
  const [confirmKick, setConfirmKick] = useState<string | null>(null)

  const handleRevoke = async (sid: string) => {
    if (revoking) return
    setConfirmKick(null)
    setRevoking(sid)
    try {
      await portalApi.deleteSession(sid)
      setSessions((prev) => prev.filter((s) => s.id !== sid))
    } catch (err: unknown) {
      const msg = extractMessage(err, t('account.sessions.kickFailed'))
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
        <div className="flex items-center gap-2 py-4 text-sm text-muted">
          <Loader2 className="h-4 w-4 animate-spin" />
          {t('common.loading')}
        </div>
      ) : error ? (
        <p className="text-sm text-red-500">{error}</p>
      ) : sessions.length === 0 ? (
        <p className="py-4 text-sm text-muted">{t('account.sessions.empty')}</p>
      ) : (
        <div className="space-y-3">
          {sessions.map((session) => (
            <div
              key={session.id}
              className="flex items-center justify-between rounded-lg border border-border bg-surface px-4 py-3"
            >
              <div className="flex items-center gap-3">
                <Monitor className="h-5 w-5 text-faint" />
                <div>
                  <p className="text-sm font-medium text-ink">
                    {parseUA(session.user_agent)}
                  </p>
                  <p className="text-xs text-muted">
                    IP: {session.ip} &middot; {t('account.sessions.lastActiveLabel')}: {formatDate(session.last_active_at)}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setConfirmKick(session.id)}
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
      <ConfirmDialog
        open={confirmKick !== null}
        title={t('account.sessions.kickConfirm')}
        loading={revoking !== null}
        onConfirm={() => confirmKick && handleRevoke(confirmKick)}
        onCancel={() => setConfirmKick(null)}
      />
    </SectionCard>
  )
}

function ConnectedExtensionsSection() {
  const { t } = useTranslation()
  const [tokens, setTokens] = useState<FormFillExtToken[]>([])
  const [loading, setLoading] = useState(true)
  const [revoking, setRevoking] = useState<string | null>(null)

  const fetchTokens = () => {
    setLoading(true)
    portalApi
      .listExtTokens()
      .then(setTokens)
      .catch(() => setTokens([]))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    fetchTokens()
  }, [])

  // Revoking an extension token immediately breaks that browser's autofill.
  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null)

  const handleRevoke = async (id: string) => {
    if (revoking) return
    setConfirmRevoke(null)
    setRevoking(id)
    try {
      await portalApi.revokeExtToken(id)
      setTokens((prev) => prev.filter((x) => x.id !== id))
      toast.success(t('account.extensions.revoked'))
    } catch (err: unknown) {
      toast.error(t('account.extensions.revokeFailed'), extractMessage(err))
    } finally {
      setRevoking(null)
    }
  }

  return (
    <SectionCard icon={Puzzle} title={t('account.extensions.title')}>
      <p className="mb-3 text-xs text-muted">{t('account.extensions.hint')}</p>
      {loading ? (
        <div className="flex items-center gap-2 py-4 text-sm text-muted">
          <Loader2 className="h-4 w-4 animate-spin" />
          {t('common.loading')}
        </div>
      ) : tokens.length === 0 ? (
        <p className="py-4 text-sm text-muted">{t('account.extensions.empty')}</p>
      ) : (
        <div className="space-y-3">
          {tokens.map((tk) => (
            <div
              key={tk.id}
              className="flex items-center justify-between rounded-lg border border-border bg-surface px-4 py-3"
            >
              <div className="flex items-center gap-3">
                <Puzzle className="h-5 w-5 text-faint" />
                <div>
                  <p className="text-sm font-medium text-ink">
                    {parseUserAgent(tk.device_label).short || tk.device_label || t('account.extensions.unknownDevice')}
                  </p>
                  <p className="text-xs text-muted">
                    {t('account.extensions.lastUsedLabel')}: {tk.last_used_at ? formatDate(tk.last_used_at) : '—'}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setConfirmRevoke(tk.id)}
                disabled={revoking === tk.id}
                className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium text-red-600 transition-colors hover:bg-red-50 disabled:opacity-50"
              >
                {revoking === tk.id ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Trash2 className="h-3.5 w-3.5" />
                )}
                {t('account.extensions.revoke')}
              </button>
            </div>
          ))}
        </div>
      )}
      <ConfirmDialog
        open={confirmRevoke !== null}
        title={t('account.extensions.revokeConfirm')}
        loading={revoking !== null}
        onConfirm={() => confirmRevoke && handleRevoke(confirmRevoke)}
        onCancel={() => setConfirmRevoke(null)}
      />
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
    <div className="rounded-xl border border-border bg-surface p-6">
      <div className="mb-4 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Icon className="h-5 w-5 text-primary" />
          <h2 className="text-base font-semibold text-ink">{title}</h2>
        </div>
        {action}
      </div>
      {children}
    </div>
  )
}
