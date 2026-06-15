// SMS OTP sign-in: phone + 6-digit code.
//
// Flow:
//   1. User types phone, clicks "Send code". Server stores a 6-digit code
//      in Redis (5 min TTL) keyed by phone and dispatches via Aliyun /
//      Tencent / Twilio (whichever the admin configured).
//   2. Cooldown: 60s before another /send is accepted for the same phone.
//   3. User types the code, clicks "Sign in". Server consumes the code,
//      issues a session cookie, returns the user payload. We then
//      window.location to /apps so AuthGuard refetches the session.
import { useState, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { useTranslation, smsOTPApi, useBootstrap } from '@mxid/shared'
import logo from '../../assets/logo.png'

export default function SMSLoginPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const bootstrap = useBootstrap()
  const enabled = bootstrap.login_methods.sms_otp

  const [phone, setPhone] = useState('')
  const [code, setCode] = useState('')
  const [sent, setSent] = useState(false)
  const [devCode, setDevCode] = useState('')
  const [cooldown, setCooldown] = useState(0)
  const [sending, setSending] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (cooldown <= 0) return
    const id = window.setTimeout(() => setCooldown((c) => c - 1), 1000)
    return () => window.clearTimeout(id)
  }, [cooldown])

  const onSend = async () => {
    if (!phone.trim() || sending || cooldown > 0) return
    setSending(true)
    setError('')
    try {
      const r = await smsOTPApi.send(phone.trim())
      setSent(true)
      setDevCode(r.dev_code || '')
      setCooldown(60)
    } catch (err) {
      const msg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message
      setError(msg || t('login.failedRetry'))
    } finally {
      setSending(false)
    }
  }

  const onLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!phone.trim() || code.length !== 6) return
    setSubmitting(true)
    setError('')
    try {
      await smsOTPApi.login(phone.trim(), code.trim())
      // Hard navigation so AuthGuard refetches /me and the SPA picks up
      // the new session cookie cleanly.
      window.location.href = '/apps'
    } catch (err) {
      const msg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message
      setError(msg || t('login.failedRetry'))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="flex min-h-screen">
      <div className="hidden lg:flex lg:w-1/2 items-center justify-center" style={{ backgroundColor: '#FAFAF7' }}>
        <img src={logo} alt="MXID" className="w-[520px] max-w-[80%] h-auto" />
      </div>
      <div className="flex w-full lg:w-1/2 items-center justify-center px-6" style={{ backgroundColor: '#0F1B3D' }}>
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.4 }}
          className="w-full max-w-sm"
        >
          <h2 className="text-3xl font-semibold tracking-tight text-white">
            {t('login.sms.title')}
          </h2>
          <p className="mt-2 text-sm text-white/55">
            {t('login.sms.subtitle')}
          </p>

          {!enabled ? (
            <div className="mt-6 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-3 text-sm text-amber-200">
              {t('login.sms.disabled')}
            </div>
          ) : (
            <form onSubmit={onLogin} className="mt-6 flex flex-col gap-4">
              <div>
                <label className="mb-1.5 block text-sm font-medium text-white/90">
                  {t('login.sms.phone')}
                </label>
                <input
                  type="tel"
                  value={phone}
                  onChange={(e) => setPhone(e.target.value)}
                  placeholder="+8613800138000"
                  autoFocus
                  className="w-full rounded-lg border border-white/25 bg-white/[0.08] px-3 py-2.5 text-sm text-white placeholder:text-white/50 outline-none transition-colors focus:border-white/60 focus:bg-white/[0.12]"
                />
              </div>
              <div>
                <label className="mb-1.5 block text-sm font-medium text-white/90">
                  {t('login.sms.code')}
                </label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]*"
                    maxLength={6}
                    value={code}
                    onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    placeholder="123456"
                    className="flex-1 rounded-lg border border-white/25 bg-white/[0.08] px-3 py-2.5 text-center font-mono tracking-widest text-white placeholder:text-white/40 outline-none transition-colors focus:border-white/60 focus:bg-white/[0.12]"
                  />
                  <button
                    type="button"
                    onClick={onSend}
                    disabled={sending || cooldown > 0 || !phone.trim()}
                    className="rounded-lg border border-white/25 bg-white/[0.08] px-3 py-2.5 text-sm font-medium text-white transition-colors hover:bg-white/[0.14] disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {cooldown > 0 ? `${cooldown}s` : sending ? t('login.sms.sending') : t('login.sms.sendCode')}
                  </button>
                </div>
              </div>
              {sent && devCode && (
                <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">
                  {t('login.sms.devCodeHint', { code: devCode })}
                </div>
              )}
              {error && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">
                  {error}
                </div>
              )}
              <button
                type="submit"
                disabled={submitting || code.length !== 6 || !phone.trim()}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-primary-hover disabled:cursor-not-allowed disabled:opacity-50"
              >
                {submitting ? t('login.submitting') : t('login.submit')}
              </button>
            </form>
          )}

          <div className="mt-6 text-center">
            <Link to="/login" className="text-sm text-white/55 hover:text-white" onClick={(e) => { e.preventDefault(); navigate('/login') }}>
              {t('login.sms.backToPassword')}
            </Link>
          </div>
        </motion.div>
      </div>
    </div>
  )
}
