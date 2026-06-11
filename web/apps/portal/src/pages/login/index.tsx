import { useState, useEffect, useCallback, useMemo, type FormEvent } from 'react'
import { useNavigate, useLocation, useSearchParams, Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { authApi, externalIdpApi, useAuthStore, useBootstrap, useTranslation } from '@mxid/shared'
import type { PublicIDP } from '@mxid/shared'
import { Eye, EyeOff, Loader2, RefreshCw } from 'lucide-react'
import logo from '../../assets/logo.png'

// resumeSSOIfAny inspects the URL for an in-flight protocol handshake
// (?protocol=cas|oidc|saml plus app_code + service) and, when present,
// fires a hard navigation back to the backend protocol endpoint so the
// ticket / code can be issued. Returns true when it took over the redirect.
function resumeSSOIfAny(sp: URLSearchParams): boolean {
  const protocol = sp.get('protocol')
  const appCode = sp.get('app_code')
  const service = sp.get('service')
  if (protocol === 'cas' && appCode && service) {
    window.location.replace(`/protocol/cas/${appCode}/login?service=${encodeURIComponent(service)}`)
    return true
  }
  return false
}

// Provider-specific brand colours for the social login buttons. Anything not
// listed falls back to neutral white-on-grey.
const IDP_BRAND: Record<string, { bg: string; label: string }> = {
  lark:   { bg: 'bg-[#00D6B9] hover:bg-[#00bda3]', label: 'Lark' },
  feishu: { bg: 'bg-[#3370FF] hover:bg-[#285ddb]', label: '飞书' },
  teams:  { bg: 'bg-[#5059C9] hover:bg-[#444cb3]', label: 'Microsoft Teams' },
}

export default function LoginPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const [searchParams] = useSearchParams()
  // Multi-tenant: URL ?tenant=<code> routes the login to that tenant. Used
  // by enterprises that share a single portal host (e.g. mxid.io/?tenant=matrixplus).
  const tenantCode = useMemo(() => searchParams.get('tenant') ?? '', [searchParams])
  const { setUser } = useAuthStore()
  // Live admin-controlled toggle: when disabled, swap form for a notice
  // so the user doesn't waste time typing into a dead form.
  const bootstrap = useBootstrap()
  const passwordEnabled = bootstrap.login_methods.password
  const idpFirst = bootstrap.login_methods.external_idp_first
  const magicLinkEnabled = bootstrap.login_methods.email_magic_link
  const smsEnabled = bootstrap.login_methods.sms_otp
  const { t } = useTranslation()

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPwd, setShowPwd] = useState(false)
  const [captchaId, setCaptchaId] = useState('')
  const [captchaImage, setCaptchaImage] = useState('')
  const [captchaCode, setCaptchaCode] = useState('')
  const [remember, setRemember] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  // MFA challenge state. Populated when /auth/login returns mfa_required.
  // Clearing the challenge returns the UI to the password step.
  const [mfaChallenge, setMfaChallenge] = useState('')
  const [mfaCode, setMfaCode] = useState('')

  // External IdPs (social login). Empty array = no buttons rendered.
  // Filtered to the current tenant when ?tenant= is set.
  const [idps, setIdps] = useState<PublicIDP[]>([])
  useEffect(() => {
    externalIdpApi.listPublic(tenantCode || undefined).then(setIdps).catch(() => {})
  }, [tenantCode])

  const loadCaptcha = useCallback(async () => {
    try {
      const data = await authApi.portalCaptcha()
      setCaptchaId(data.captcha_id)
      setCaptchaImage(data.captcha_image)
      setCaptchaCode('')
    } catch {
      // ignore
    }
  }, [])

  useEffect(() => {
    loadCaptcha()
  }, [loadCaptcha])

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    if (!username.trim() || !password) return
    if (!captchaCode) {
      setError(t('login.enterCaptcha'))
      return
    }

    setLoading(true)
    setError('')

    try {
      const resp = await authApi.portalLogin({
        username: username.trim(),
        password,
        captcha_id: captchaId,
        captcha_code: captchaCode,
        remember,
        tenant: tenantCode || undefined,
      })
      // Server short-circuits before setting cookies when MFA is on. Swap
      // the UI into "enter TOTP code" mode and stash the opaque challenge.
      if (resp?.mfa_required && resp.challenge) {
        setMfaChallenge(resp.challenge)
        setMfaCode('')
        setError('')
        return
      }
      const user = await authApi.portalMe()
      setUser(user)
      if (resumeSSOIfAny(searchParams)) return
      const from = (location.state as { from?: string })?.from || '/apps'
      navigate(from, { replace: true })
    } catch (err: unknown) {
      const msg =
        err instanceof Error ? err.message : t('login.failedRetry')
      setError(msg)
      loadCaptcha()
    } finally {
      setLoading(false)
    }
  }

  const handleVerifyMfa = async (e: FormEvent) => {
    e.preventDefault()
    if (mfaCode.length !== 6) return
    setLoading(true)
    setError('')
    try {
      await authApi.portalVerifyMFA({
        challenge: mfaChallenge,
        code: mfaCode,
        remember,
      })
      const user = await authApi.portalMe()
      setUser(user)
      if (resumeSSOIfAny(searchParams)) return
      const from = (location.state as { from?: string })?.from || '/apps'
      navigate(from, { replace: true })
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : t('login.invalidPwd')
      // Backend consumes the challenge on any verify attempt — wrong code
      // means the user must restart from password step.
      setError(msg)
      setMfaChallenge('')
      setMfaCode('')
      setPassword('')
      loadCaptcha()
    } finally {
      setLoading(false)
    }
  }

  const cancelMfa = () => {
    setMfaChallenge('')
    setMfaCode('')
    setError('')
    loadCaptcha()
  }

  return (
    <div className="flex min-h-screen">
      {/* Left — Logo */}
      <div className="hidden lg:flex lg:w-1/2 items-center justify-center" style={{ backgroundColor: '#FAFAF7' }}>
        <motion.div
          initial={{ opacity: 0, scale: 0.96 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.5 }}
          className="flex items-center justify-center"
        >
          <img src={logo} alt="MXID" className="w-[520px] max-w-[80%] h-auto" />
        </motion.div>
      </div>

      {/* Right — Login Form */}
      <div className="flex w-full lg:w-1/2 items-center justify-center px-6" style={{ backgroundColor: '#0F1B3D' }}>
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.4 }}
          className="w-full max-w-sm"
        >
          {/* Mobile logo */}
          <div className="mb-8 text-center lg:hidden">
            <img src={logo} alt="MXID" className="mx-auto h-14 w-auto" />
          </div>

          <div className="mb-8">
            <h2 className="text-3xl font-semibold tracking-tight text-white">
              {mfaChallenge ? t('login.mfa') : t('login.welcomePortal')}
            </h2>
            <p className="mt-2 text-sm text-white/55">
              {mfaChallenge
                ? t('login.mfaHint')
                : t('login.subtitlePortal')}
            </p>
          </div>

          {!mfaChallenge && idpFirst && idps.length > 0 && (
            <div className="mb-6">
              <div className="grid grid-cols-2 gap-2">
                {idps.map((idp) => {
                  const brand = IDP_BRAND[idp.type] ?? { bg: 'bg-white/10 hover:bg-white/20', label: idp.name }
                  return (
                    <a
                      key={idp.id}
                      href={externalIdpApi.startURL(idp.code, undefined, tenantCode || undefined)}
                      className={`flex items-center justify-center gap-2 rounded-lg px-3 py-2 text-sm font-medium text-white transition-colors ${brand.bg}`}
                    >
                      {idp.icon ? (
                        <img src={idp.icon} alt={idp.name} className="h-4 w-4" />
                      ) : null}
                      {idp.name || brand.label}
                    </a>
                  )
                })}
              </div>
              <div className="mt-4 flex items-center gap-3 text-xs text-white/40">
                <div className="h-px flex-1 bg-white/10" />
                <span>{t('login.socialDivider')}</span>
                <div className="h-px flex-1 bg-white/10" />
              </div>
            </div>
          )}

          {mfaChallenge ? (
            <form onSubmit={handleVerifyMfa} className="flex flex-col gap-4">
              <div>
                <label className="mb-1.5 block text-sm font-medium text-white/90">
{t('account.mfa.verifyCode')}
                </label>
                <input
                  autoFocus
                  inputMode="numeric"
                  pattern="[0-9]*"
                  maxLength={6}
                  value={mfaCode}
                  onChange={(e) =>
                    setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))
                  }
                  placeholder="••••••"
                  className="w-full rounded-lg border border-white/25 bg-white/[0.08] px-3 py-2.5 text-center text-lg font-mono tracking-widest text-white placeholder:text-white/40 outline-none transition-colors focus:border-white/60 focus:bg-white/[0.12]"
                />
              </div>
              {error && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300"
                >
                  {error}
                </motion.div>
              )}
              <button
                type="submit"
                disabled={loading || mfaCode.length !== 6}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-primary-hover disabled:cursor-not-allowed disabled:opacity-50"
              >
                {loading && <Loader2 className="h-4 w-4 animate-spin" />}
                {loading ? t('login.mfaSubmitting') : t('login.mfaSubmit')}
              </button>
              <button
                type="button"
                onClick={cancelMfa}
                className="text-center text-xs text-white/55 hover:text-white"
              >
{t('login.mfaBack')}
              </button>
            </form>
          ) : passwordEnabled ? (
          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            <div>
              <label className="mb-1.5 block text-sm font-medium text-white/90">
{t('login.username')}
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder={t('login.placeholderUsername')}
                autoComplete="username"
                autoFocus
                className="w-full rounded-lg border border-white/25 bg-white/[0.08] px-3 py-2.5 text-sm text-white placeholder:text-white/50 outline-none transition-colors focus:border-white/60 focus:bg-white/[0.12]"
              />
            </div>

            <div>
              <label className="mb-1.5 block text-sm font-medium text-white/90">
{t('login.password')}
              </label>
              <div className="relative">
                <input
                  type={showPwd ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={t('login.placeholderPassword')}
                  autoComplete="current-password"
                  className="w-full rounded-lg border border-white/25 bg-white/[0.08] px-3 py-2.5 pr-10 text-sm text-white placeholder:text-white/50 outline-none transition-colors focus:border-white/60 focus:bg-white/[0.12]"
                />
                <button
                  type="button"
                  onClick={() => setShowPwd(!showPwd)}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-white/60 hover:text-white"
                >
                  {showPwd ? (
                    <EyeOff className="h-4 w-4" />
                  ) : (
                    <Eye className="h-4 w-4" />
                  )}
                </button>
              </div>
            </div>

            <div>
              <label className="mb-1.5 block text-sm font-medium text-white/90">
                {t('login.captcha')}
              </label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={captchaCode}
                  onChange={(e) => setCaptchaCode(e.target.value)}
                  placeholder={t('login.captchaPlaceholder')}
                  maxLength={5}
                  autoComplete="off"
                  className="flex-1 rounded-lg border border-white/25 bg-white/[0.08] px-3 py-2.5 text-sm text-white placeholder:text-white/50 outline-none transition-colors focus:border-white/60 focus:bg-white/[0.12]"
                />
                <div className="flex items-center gap-1">
                  {captchaImage ? (
                    <img
                      src={captchaImage}
                      alt={t('login.captcha')}
                      className="h-[38px] w-[100px] cursor-pointer rounded-lg border border-white/25 bg-white"
                      onClick={loadCaptcha}
                      title={t('login.captchaClickRefresh')}
                    />
                  ) : (
                    <div className="flex h-[38px] w-[100px] items-center justify-center rounded-lg border border-white/25 bg-white/[0.08] text-xs text-white/60">
{t('login.captchaLoading')}
                    </div>
                  )}
                  <button
                    type="button"
                    onClick={loadCaptcha}
                    className="rounded-lg p-2 text-white/60 transition-colors hover:bg-white/10 hover:text-white"
                    title={t('login.refreshCaptcha')}
                  >
                    <RefreshCw className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            </div>

            <div className="flex items-center justify-between">
              <label className="flex cursor-pointer items-center gap-2 text-sm text-white/80 select-none">
                <input
                  type="checkbox"
                  checked={remember}
                  onChange={(e) => setRemember(e.target.checked)}
                  className="h-4 w-4 rounded border-white/30 bg-white/10 text-primary focus:ring-primary/30"
                />
                {t('login.rememberMe')}
              </label>
              <Link to="/password/forgot" className="text-sm text-white/70 hover:text-white">
                {t('login.forgotPassword')}
              </Link>
            </div>
            {(magicLinkEnabled || smsEnabled) && (
              <div className="flex items-center justify-center gap-4 text-xs">
                {magicLinkEnabled && (
                  <Link to="/login/magic-link" className="text-white/55 hover:text-white">
                    {t('login.magicLink.entry')}
                  </Link>
                )}
                {smsEnabled && (
                  <Link to="/login/sms" className="text-white/55 hover:text-white">
                    {t('login.sms.entry')}
                  </Link>
                )}
              </div>
            )}

            {error && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300"
              >
                {error}
              </motion.div>
            )}

            <button
              type="submit"
              disabled={loading || !username.trim() || !password}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-primary-hover disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading && <Loader2 className="h-4 w-4 animate-spin" />}
              {loading ? t('login.submitting') : t('login.submit')}
            </button>
          </form>
          ) : (
            <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 px-3 py-3 text-sm text-yellow-200">
{t('login.passwordDisabledHint')}
            </div>
          )}

          {!mfaChallenge && !idpFirst && idps.length > 0 && (
            <div className="mt-6">
              <div className="mb-3 flex items-center gap-3 text-xs text-white/40">
                <div className="h-px flex-1 bg-white/10" />
                <span>{t('login.socialDivider')}</span>
                <div className="h-px flex-1 bg-white/10" />
              </div>
              <div className="grid grid-cols-2 gap-2">
                {idps.map((idp) => {
                  const brand = IDP_BRAND[idp.type] ?? { bg: 'bg-white/10 hover:bg-white/20', label: idp.name }
                  return (
                    <a
                      key={idp.id}
                      href={externalIdpApi.startURL(idp.code, undefined, tenantCode || undefined)}
                      className={`flex items-center justify-center gap-2 rounded-lg px-3 py-2 text-sm font-medium text-white transition-colors ${brand.bg}`}
                    >
                      {idp.icon ? (
                        <img src={idp.icon} alt={idp.name} className="h-4 w-4" />
                      ) : null}
                      {idp.name || brand.label}
                    </a>
                  )
                })}
              </div>
            </div>
          )}

          <p className="mt-8 text-center text-xs text-white/55">
            MXID Identity Platform
          </p>
        </motion.div>
      </div>
    </div>
  )
}
