// Reset-password page. Consumes the one-shot token from the URL and posts
// the new password to /api/v1/portal-public/password/reset. Backend runs
// the full policy + history checks; we surface its error message inline so
// the user knows whether the password was too short / reused / etc.
import { useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Eye, EyeOff } from 'lucide-react'
import { useTranslation, passwordResetApi } from '@mxid/shared'
import logo from '../../assets/logo.png'

export default function ResetPasswordPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const token = params.get('token') || ''
  const [pwd, setPwd] = useState('')
  const [pwd2, setPwd2] = useState('')
  const [showPwd, setShowPwd] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const [done, setDone] = useState(false)

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    if (!token) {
      setError(t('portal.pwdReset.tokenMissing'))
      return
    }
    if (pwd.length < 6) {
      setError(t('portal.pwdReset.tooShort'))
      return
    }
    if (pwd !== pwd2) {
      setError(t('portal.pwdReset.mismatch'))
      return
    }
    setSubmitting(true)
    try {
      await passwordResetApi.reset(token, pwd)
      setDone(true)
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
            {t('portal.pwdReset.resetTitle')}
          </h2>
          <p className="mt-2 text-sm text-white/55">
            {t('portal.pwdReset.resetSubtitle')}
          </p>

          {done ? (
            <div className="mt-6 space-y-4 text-sm text-white">
              <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-3">
                {t('portal.pwdReset.successHint')}
              </div>
              <button
                onClick={() => navigate('/login')}
                className="w-full rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-white hover:bg-primary-hover"
              >
                {t('portal.pwdReset.gotoLogin')}
              </button>
            </div>
          ) : (
            <form onSubmit={onSubmit} className="mt-6 flex flex-col gap-4">
              <div>
                <label className="mb-1.5 block text-sm font-medium text-white/90">
                  {t('portal.pwdReset.newPwd')}
                </label>
                <div className="relative">
                  <input
                    type={showPwd ? 'text' : 'password'}
                    value={pwd}
                    onChange={(e) => setPwd(e.target.value)}
                    autoFocus
                    className="w-full rounded-lg border border-white/25 bg-white/[0.08] px-3 py-2.5 pr-10 text-sm text-white placeholder:text-white/50 outline-none transition-colors focus:border-white/60 focus:bg-white/[0.12]"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPwd((v) => !v)}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded p-1 text-white/40 hover:text-white"
                  >
                    {showPwd ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </div>
              <div>
                <label className="mb-1.5 block text-sm font-medium text-white/90">
                  {t('portal.pwdReset.confirmPwd')}
                </label>
                <input
                  type={showPwd ? 'text' : 'password'}
                  value={pwd2}
                  onChange={(e) => setPwd2(e.target.value)}
                  className="w-full rounded-lg border border-white/25 bg-white/[0.08] px-3 py-2.5 text-sm text-white placeholder:text-white/50 outline-none transition-colors focus:border-white/60 focus:bg-white/[0.12]"
                />
              </div>
              {error && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">
                  {error}
                </div>
              )}
              <button
                type="submit"
                disabled={submitting || !pwd || !pwd2}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-primary-hover disabled:cursor-not-allowed disabled:opacity-50"
              >
                {submitting ? t('portal.pwdReset.resetting') : t('portal.pwdReset.resetBtn')}
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
