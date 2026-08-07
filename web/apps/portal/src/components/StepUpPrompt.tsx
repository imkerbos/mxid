import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { authApi, useTranslation, type StepUpMethod } from '@mxid/shared'
import { Button, Field, Input } from '@mxid/shared/ui'
import { toast, extractMessage } from '@mxid/shared/ui/toast'
import { Loader2 } from 'lucide-react'

/**
 * StepUpPrompt — the portal's sudo-window challenge, shared by the global
 * step-up modal and the standalone /step-up page.
 *
 * The challenge is whatever the ACCOUNT can answer, resolved from the server
 * (GET /auth/step-up) rather than assumed:
 *
 *  - 'totp'     — an authenticator is enrolled. Six digits, auto-submitted.
 *  - 'password' — no factor enrolled, so we re-ask for the login password.
 *    Without this branch every step-up-gated action (form-fill reveal, revoking
 *    a connected extension) was permanently unreachable for accounts that never
 *    enrolled MFA — the prompt demanded a code they had no way to produce.
 *  - 'none'     — external-IdP account with neither. Nothing to verify against,
 *    so we point them at enrollment instead of showing a dead input.
 */
export default function StepUpPrompt({
  onVerified,
  onCancel,
}: {
  onVerified: () => void
  onCancel?: () => void
}) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [method, setMethod] = useState<StepUpMethod | null>(null)
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    let alive = true
    authApi
      .portalStepUpMethod()
      .then((r) => alive && setMethod(r.method))
      // A failed probe must not strand the user on a spinner: fall back to the
      // strongest challenge and let the server refuse it if that was wrong.
      .catch(() => alive && setMethod('totp'))
    return () => {
      alive = false
    }
  }, [])

  const submit = async () => {
    if (submitting || !method) return
    const proof = method === 'totp' ? { code } : { password }
    if (method === 'totp' ? code.length !== 6 : password.length === 0) return
    setSubmitting(true)
    try {
      await authApi.portalStepUp(proof)
      toast.success(t('stepup.success'))
      setCode('')
      setPassword('')
      onVerified()
    } catch (e) {
      toast.error(t('stepup.failed'), extractMessage(e))
    } finally {
      setSubmitting(false)
    }
  }

  // Auto-submit once six digits are in — a TOTP code has no other length, so an
  // extra click buys nothing. Password never auto-submits (any length is valid).
  useEffect(() => {
    if (method === 'totp' && code.length === 6 && !submitting) submit()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [code, method])

  if (!method) {
    return (
      <div className="flex items-center justify-center py-8">
        <Loader2 className="h-5 w-5 animate-spin text-primary" />
      </div>
    )
  }

  if (method === 'none') {
    return (
      <div className="space-y-4">
        <p className="text-sm text-muted">{t('stepup.noMethod')}</p>
        <div className="flex justify-end gap-2">
          {onCancel && (
            <Button variant="secondary" onClick={onCancel}>
              {t('common.cancel')}
            </Button>
          )}
          <Button onClick={() => navigate('/security')}>{t('stepup.setUpMfa')}</Button>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted">
        {method === 'totp' ? t('stepup.hint') : t('stepup.passwordHint')}
      </p>
      {method === 'totp' ? (
        <Input
          autoFocus
          inputMode="numeric"
          maxLength={6}
          placeholder="000000"
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
          onKeyDown={(e) => e.key === 'Enter' && submit()}
        />
      ) : (
        <Field label={t('stepup.passwordLabel')}>
          <Input
            autoFocus
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && submit()}
          />
        </Field>
      )}
      <div className="flex justify-end gap-2">
        {onCancel && (
          <Button variant="secondary" onClick={onCancel} disabled={submitting}>
            {t('common.cancel')}
          </Button>
        )}
        <Button
          onClick={submit}
          loading={submitting}
          disabled={method === 'totp' ? code.length !== 6 : password.length === 0}
        >
          {t('stepup.verify')}
        </Button>
      </div>
    </div>
  )
}
