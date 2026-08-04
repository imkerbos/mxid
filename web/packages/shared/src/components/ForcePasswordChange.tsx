import { useState, type FormEvent } from 'react'
import { KeyRound, Loader2, LogOut } from 'lucide-react'
import { useAuthStore } from '../hooks/use-auth-store'
import { useTranslation } from '../i18n'
import { toast } from '../ui/toast'

/**
 * ForcePasswordChange — full-screen blocking gate shown when the backend
 * password gate reports this account must choose a new password before doing
 * anything else (HTTP 403, code 40333). Every other route and API call returns
 * that same 403 until it is done, so this renders instead of the app rather
 * than alongside it — a half-broken page full of failed requests tells the user
 * nothing about what is being asked of them.
 *
 * Reached two ways: an administrator reset the password (the reset has always
 * promised the user would have to choose their own, and now it is true), or the
 * account still carries the password it was seeded with.
 *
 * Shared between console and portal because the demand is identical on both and
 * the seeded administrator hits it on the console.
 */
export default function ForcePasswordChange({
  changePassword,
  logout,
  toLogin,
}: {
  /** Namespace-specific change-password call — the one route the gate allows. */
  changePassword: (oldPassword: string, newPassword: string) => Promise<unknown>
  /** Best-effort server-side logout. */
  logout: () => Promise<unknown>
  /** Send the browser to the sign-in screen. */
  toLogin: () => void
}) {
  const { t } = useTranslation()
  const setPasswordChangeRequired = useAuthStore((s) => s.setPasswordChangeRequired)
  const clear = useAuthStore((s) => s.clear)

  const [oldPwd, setOldPwd] = useState('')
  const [newPwd, setNewPwd] = useState('')
  const [confirm, setConfirm] = useState('')
  const [saving, setSaving] = useState(false)

  const mismatch = confirm.length > 0 && newPwd !== confirm
  const ready = oldPwd.length > 0 && newPwd.length > 0 && newPwd === confirm && !saving

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!ready) return
    setSaving(true)
    try {
      await changePassword(oldPwd, newPwd)
      toast.success(t('account.password.changed'))
      // The server-side flag self-heals — the gate clears it on the next
      // request once the database says nothing is owed — so dropping the client
      // flag is enough to let the app render.
      setPasswordChangeRequired(false)
    } catch (err) {
      const msg = err instanceof Error ? err.message : t('common.failed')
      toast.error(t('common.failed'), msg)
    } finally {
      setSaving(false)
    }
  }

  const signOut = () => {
    // The escape hatch has to work even when the call fails.
    logout().catch(() => {})
    clear()
    toLogin()
  }

  const field =
    'w-full rounded-lg border border-border px-3 py-2 text-sm text-ink outline-none focus:border-primary focus:ring-2 focus:ring-primary/20'

  return (
    <div className="flex min-h-screen items-center justify-center bg-canvas p-4">
      <div className="w-full max-w-md rounded-2xl border border-border bg-surface p-6 shadow-xl">
        <div className="mb-4 flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10 text-primary">
            <KeyRound className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-ink">{t('account.password.forceTitle')}</h1>
            <p className="text-sm text-muted">{t('account.password.forceSubtitle')}</p>
          </div>
        </div>

        <form onSubmit={submit} className="space-y-4">
          <div>
            <label className="mb-1 block text-xs font-medium text-muted">
              {t('account.password.old')}
            </label>
            <input
              autoFocus
              type="password"
              autoComplete="current-password"
              value={oldPwd}
              onChange={(e) => setOldPwd(e.target.value)}
              className={field}
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-muted">
              {t('account.password.new')}
            </label>
            <input
              type="password"
              autoComplete="new-password"
              value={newPwd}
              onChange={(e) => setNewPwd(e.target.value)}
              className={field}
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-muted">
              {t('account.password.confirm')}
            </label>
            <input
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              className={field}
            />
            {mismatch && (
              <p className="mt-1 text-xs text-red-600">{t('account.password.mismatch')}</p>
            )}
          </div>
          <button
            type="submit"
            disabled={!ready}
            className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-60"
          >
            {saving && <Loader2 className="h-4 w-4 animate-spin" />}
            {t('account.password.forceSubmit')}
          </button>
        </form>

        <button
          onClick={signOut}
          className="mt-4 inline-flex w-full items-center justify-center gap-1.5 text-xs text-faint hover:text-ink"
        >
          <LogOut className="h-3.5 w-3.5" />
          {t('nav.logout')}
        </button>
      </div>
    </div>
  )
}
