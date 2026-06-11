// Magic-link sign-in: user enters email, backend mails a one-shot link.
// No password — possession of the email proves identity. Gated by the
// admin's login_methods.email_magic_link toggle (the /send endpoint also
// returns 403 when disabled, so we surface the same hint here on bootstrap).
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { useTranslation, magicLinkApi, useBootstrap } from '@mxid/shared'
import logo from '../../assets/logo.png'

export default function MagicLinkLoginPage() {
  const { t } = useTranslation()
  const bootstrap = useBootstrap()
  const enabled = bootstrap.login_methods.email_magic_link
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
      const r = await magicLinkApi.send(email.trim())
      setSent(true)
      setDevLink(r.dev_link || '')
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
            {t('login.magicLink.title')}
          </h2>
          <p className="mt-2 text-sm text-white/55">
            {t('login.magicLink.subtitle')}
          </p>

          {!enabled ? (
            <div className="mt-6 rounded-lg border border-yellow-500/30 bg-yellow-500/10 px-3 py-3 text-sm text-yellow-200">
              {t('login.magicLink.disabled')}
            </div>
          ) : sent ? (
            <div className="mt-6 space-y-4 text-sm text-white">
              <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-3">
                {t('login.magicLink.sentHint')}
              </div>
              {devLink && (
                <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 px-3 py-3 text-xs">
                  <p className="mb-1 text-yellow-200">{t('login.magicLink.devLinkHint')}</p>
                  <a href={devLink} className="break-all text-yellow-100 underline">{devLink}</a>
                </div>
              )}
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
                disabled={submitting || !email.trim()}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-primary-hover disabled:cursor-not-allowed disabled:opacity-50"
              >
                {submitting ? t('login.magicLink.sending') : t('login.magicLink.sendBtn')}
              </button>
            </form>
          )}

          <div className="mt-6 text-center">
            <Link to="/login" className="text-sm text-white/55 hover:text-white">
              {t('login.magicLink.backToPassword')}
            </Link>
          </div>
        </motion.div>
      </div>
    </div>
  )
}
