// Forgot-password page. Public — no auth required.
//
// Submits {email} to /api/v1/portal-public/password/forgot and renders a
// "check your inbox" confirmation regardless of whether the email matches
// a user (the backend deliberately doesn't disclose, to avoid email
// enumeration). When SMTP isn't configured the backend returns a dev_link
// we render inline so first-deploy admins can click through.
import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { useTranslation, passwordResetApi } from '@mxid/shared'
import logo from '../../assets/logo.png'

export default function ForgotPasswordPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [sent, setSent] = useState(false)
  const [devLink, setDevLink] = useState('')
  const [error, setError] = useState('')

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!email.trim()) return
    setSubmitting(true)
    setError('')
    try {
      const resp = await passwordResetApi.forgot(email.trim())
      setSent(true)
      setDevLink(resp.dev_link || '')
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
            {t('portal.pwdReset.forgotTitle')}
          </h2>
          <p className="mt-2 text-sm text-white/55">
            {t('portal.pwdReset.forgotSubtitle')}
          </p>

          {sent ? (
            <div className="mt-6 space-y-4 text-sm text-white">
              <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-3">
                {t('portal.pwdReset.sentHint')}
              </div>
              {devLink && (
                <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-3 text-xs">
                  <p className="mb-1 text-amber-200">{t('portal.pwdReset.devLinkHint')}</p>
                  <a href={devLink} className="break-all text-amber-100 underline">{devLink}</a>
                </div>
              )}
              <button
                onClick={() => navigate('/login')}
                className="w-full rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-white hover:bg-primary-hover"
              >
                {t('portal.pwdReset.backToLogin')}
              </button>
            </div>
          ) : (
            <form onSubmit={onSubmit} className="mt-6 flex flex-col gap-4">
              <div>
                <label className="mb-1.5 block text-sm font-medium text-white/90">
                  {t('account.fields.email')}
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  autoFocus
                  className="w-full rounded-lg border border-white/25 bg-surface/[0.08] px-3 py-2.5 text-sm text-white placeholder:text-white/50 outline-none transition-colors focus:border-white/60 focus:bg-surface/[0.12]"
                />
              </div>
              {error && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">
                  {error}
                </div>
              )}
              <button
                type="submit"
                disabled={submitting || !email.trim()}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-primary-hover disabled:cursor-not-allowed disabled:opacity-50"
              >
                {submitting ? t('portal.pwdReset.sending') : t('portal.pwdReset.sendBtn')}
              </button>
              <Link to="/login" className="text-center text-xs text-white/55 hover:text-white">
                {t('portal.pwdReset.backToLogin')}
              </Link>
            </form>
          )}
        </motion.div>
      </div>
    </div>
  )
}
