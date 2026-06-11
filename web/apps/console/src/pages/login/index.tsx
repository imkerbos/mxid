import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { authApi, useAuthStore, useBootstrap, useTranslation } from '@mxid/shared'
import { Eye, EyeOff, Loader2, RefreshCw } from 'lucide-react'
import logo from '../../assets/logo.png'

export default function LoginPage() {
  const navigate = useNavigate()
  const { setUser } = useAuthStore()
  const bootstrap = useBootstrap()
  const passwordEnabled = bootstrap.login_methods.password
  const { t } = useTranslation()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [captchaId, setCaptchaId] = useState('')
  const [captchaImage, setCaptchaImage] = useState('')
  const [captchaCode, setCaptchaCode] = useState('')
  const [remember, setRemember] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  // MFA challenge state — set when /auth/login returns mfa_required.
  const [mfaChallenge, setMfaChallenge] = useState('')
  const [mfaCode, setMfaCode] = useState('')

  const loadCaptcha = useCallback(async () => {
    try {
      const data = await authApi.captcha()
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

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!username || !password) {
      setError(t('login.enterUserPwd'))
      return
    }
    if (!captchaCode) {
      setError(t('login.enterCaptcha'))
      return
    }

    setLoading(true)
    setError('')

    try {
      const resp = await authApi.login({ username, password, captcha_id: captchaId, captcha_code: captchaCode, remember })
      if (resp?.mfa_required && resp.challenge) {
        setMfaChallenge(resp.challenge)
        setMfaCode('')
        setError('')
        return
      }
      const user = await authApi.me()
      setUser(user)
      navigate('/dashboard', { replace: true })
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : t('login.failedRetry')
      setError(msg)
      loadCaptcha()
    } finally {
      setLoading(false)
    }
  }

  const handleVerifyMfa = async (e: React.FormEvent) => {
    e.preventDefault()
    if (mfaCode.length !== 6) return
    setLoading(true)
    setError('')
    try {
      await authApi.consoleVerifyMFA({ challenge: mfaChallenge, code: mfaCode, remember })
      const user = await authApi.me()
      setUser(user)
      navigate('/dashboard', { replace: true })
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : t('login.invalidPwd')
      // Challenge is single-use; on failure, restart from password.
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
      <div className="flex w-full lg:w-1/2 items-center justify-center px-6" style={{ backgroundColor: '#1E2433' }}>
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
              {mfaChallenge ? t('login.mfa') : t('login.welcomeConsole')}
            </h2>
            <p className="mt-2 text-sm text-white/55">
              {mfaChallenge ? t('login.mfaHint') : t('login.subtitleConsole')}
            </p>
          </div>

          {mfaChallenge ? (
            <form onSubmit={handleVerifyMfa} className="space-y-5">
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
                  className="w-full rounded-lg border border-white/25 bg-white/[0.08] px-4 py-2.5 text-center text-lg font-mono tracking-widest text-white placeholder:text-white/40 outline-none transition-colors focus:border-white/60 focus:bg-white/[0.12]"
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
                className="block w-full text-center text-xs text-white/55 hover:text-white"
              >
{t('login.mfaBack')}
              </button>
            </form>
          ) : passwordEnabled ? (
          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="mb-1.5 block text-sm font-medium text-white/90">
{t('login.username')}
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full rounded-lg border border-white/25 bg-white/[0.08] px-4 py-2.5 text-sm text-white placeholder:text-white/50 outline-none transition-colors focus:border-white/60 focus:bg-white/[0.12]"
                placeholder={t('login.placeholderUsername')}
                autoComplete="username"
                autoFocus
              />
            </div>

            <div>
              <label className="mb-1.5 block text-sm font-medium text-white/90">
{t('login.password')}
              </label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full rounded-lg border border-white/25 bg-white/[0.08] px-4 py-2.5 pr-10 text-sm text-white placeholder:text-white/50 outline-none transition-colors focus:border-white/60 focus:bg-white/[0.12]"
                  placeholder={t('login.placeholderPassword')}
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-white/60 hover:text-white"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            <div>
              <label className="mb-1.5 block text-sm font-medium text-white/90">
                {t('login.captcha')}
              </label>
              <div className="flex items-center gap-3">
                <input
                  type="text"
                  value={captchaCode}
                  onChange={(e) => setCaptchaCode(e.target.value)}
                  className="flex-1 rounded-lg border border-white/25 bg-white/[0.08] px-4 py-2.5 text-sm text-white placeholder:text-white/50 outline-none transition-colors focus:border-white/60 focus:bg-white/[0.12]"
                  placeholder={t('login.captchaPlaceholder')}
                  maxLength={5}
                  autoComplete="off"
                />
                <div className="flex items-center gap-1.5">
                  {captchaImage ? (
                    <img
                      src={captchaImage}
                      alt={t('login.captcha')}
                      className="h-[42px] w-[120px] cursor-pointer rounded-lg border border-white/25 bg-white"
                      onClick={loadCaptcha}
                      title={t('login.captchaClickRefresh')}
                    />
                  ) : (
                    <div className="flex h-[42px] w-[120px] items-center justify-center rounded-lg border border-white/25 bg-white/[0.08] text-xs text-white/60">
{t('login.captchaLoading')}
                    </div>
                  )}
                  <button
                    type="button"
                    onClick={loadCaptcha}
                    className="rounded-lg p-2 text-white/60 transition-colors hover:bg-white/10 hover:text-white"
                    title={t('login.refreshCaptcha')}
                  >
                    <RefreshCw className="h-4 w-4" />
                  </button>
                </div>
              </div>
            </div>

            <label className="flex cursor-pointer items-center gap-2 text-sm text-white/80 select-none">
              <input
                type="checkbox"
                checked={remember}
                onChange={(e) => setRemember(e.target.checked)}
                className="h-4 w-4 rounded border-white/30 bg-white/10 text-primary focus:ring-primary/30"
              />
{t('login.rememberMe')}
            </label>

            {error && (
              <motion.div
                initial={{ opacity: 0, y: -4 }}
                animate={{ opacity: 1, y: 0 }}
                className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300"
              >
                {error}
              </motion.div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-primary-hover disabled:opacity-60"
            >
              {loading && <Loader2 className="h-4 w-4 animate-spin" />}
              {loading ? t('login.submitting') : t('login.submit')}
            </button>
          </form>
          ) : (
            <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 px-3 py-3 text-sm text-yellow-200">
{t('login.passwordDisabled')}
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



// hot reload test
// watch test 1779482430
// fsevents test 1779482526
// real watch test 1779482552
// debug test 1779482627
// fswatch hot reload 1779482918
// direct fswatch test
