import { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { appApi, useTranslation } from '@mxid/shared'
import { Field, Input, Button } from '../../components/ui'
import { toast, extractMessage } from '../../components/ui/toast'

// SharedCredentialPanel — admin config of a form-fill app's SHARED service
// account (credential_mode=shared: one account all authorized users fill with).
// The secret lives outside protocol_config (a separate step-up-gated endpoint),
// so it is not part of the declarative protocol-config form. The password is
// write-only: the API never echoes it (has_credential flags presence), so a blank
// password on save keeps the existing one. Only shown for form apps; when the
// mode is per_user it renders a note instead (users store their own credential).
export default function SharedCredentialPanel({ appId, mode }: { appId: string; mode: string }) {
  const { t } = useTranslation()
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [clearing, setClearing] = useState(false)
  const [hasCredential, setHasCredential] = useState(false)
  const [account, setAccount] = useState('')
  const [password, setPassword] = useState('')

  useEffect(() => {
    let alive = true
    setLoading(true)
    appApi
      .getSharedCredential(appId)
      .then((r) => {
        if (!alive) return
        setHasCredential(r.has_credential)
        setAccount(r.account || '')
      })
      .catch(() => {
        if (alive) {
          setHasCredential(false)
          setAccount('')
        }
      })
      .finally(() => {
        if (alive) setLoading(false)
      })
    return () => {
      alive = false
    }
  }, [appId])

  const save = async () => {
    if (!account.trim()) {
      toast.error(t('apps.detail.sharedCred.accountRequired'))
      return
    }
    // Editing an existing credential with a blank password keeps the old one.
    if (!hasCredential && !password) {
      toast.error(t('apps.detail.sharedCred.passwordRequired'))
      return
    }
    setSaving(true)
    try {
      await appApi.setSharedCredential(appId, account.trim(), password)
      toast.success(t('apps.detail.sharedCred.saved'))
      setHasCredential(true)
      setPassword('')
    } catch (err) {
      toast.error(t('apps.detail.sharedCred.saveFailed'), extractMessage(err))
    } finally {
      setSaving(false)
    }
  }

  const clear = async () => {
    setClearing(true)
    try {
      await appApi.deleteSharedCredential(appId)
      toast.success(t('apps.detail.sharedCred.cleared'))
      setHasCredential(false)
      setAccount('')
      setPassword('')
    } catch (err) {
      toast.error(t('apps.detail.sharedCred.clearFailed'), extractMessage(err))
    } finally {
      setClearing(false)
    }
  }

  const box = 'mt-6 rounded-lg border border-line bg-surface-muted/40 px-4 py-4'

  if (mode !== 'shared') {
    return (
      <div className={box}>
        <h4 className="text-sm font-medium text-ink">{t('apps.detail.sharedCred.title')}</h4>
        <p className="mt-1 text-xs text-muted">{t('apps.detail.sharedCred.perUserNote')}</p>
      </div>
    )
  }

  return (
    <div className={box}>
      <h4 className="text-sm font-medium text-ink">{t('apps.detail.sharedCred.title')}</h4>
      <p className="mt-1 text-xs text-muted">{t('apps.detail.sharedCred.hint')}</p>

      {loading ? (
        <div className="flex items-center justify-center py-8">
          <Loader2 className="h-5 w-5 animate-spin text-faint" />
        </div>
      ) : (
        <div className="mt-3 space-y-3">
          <p className="text-xs">
            {hasCredential ? (
              <span className="text-success">{t('apps.detail.sharedCred.stateSet')}</span>
            ) : (
              <span className="text-warning">{t('apps.detail.sharedCred.stateUnset')}</span>
            )}
          </p>
          <Field label={t('apps.detail.sharedCred.account')}>
            <Input value={account} onChange={(e) => setAccount(e.target.value)} placeholder="svc-wiki" />
          </Field>
          <Field label={t('apps.detail.sharedCred.password')}>
            <Input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={hasCredential ? t('apps.detail.sharedCred.passwordKeep') : ''}
              autoComplete="new-password"
            />
          </Field>
          <div className="flex justify-between pt-1">
            {hasCredential ? (
              <Button type="button" variant="ghost" onClick={clear} loading={clearing}>
                {t('apps.detail.sharedCred.clear')}
              </Button>
            ) : (
              <span />
            )}
            <Button type="button" onClick={save} loading={saving}>
              {t('common.save')}
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
