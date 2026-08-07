import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from '@mxid/shared'
import { Button } from '@mxid/shared/ui'
import { ShieldCheck } from 'lucide-react'
import StepUpPrompt from '../../components/StepUpPrompt'

/**
 * StepUpPage — the landing page the browser extension opens when its sudo
 * window has lapsed (the credential-reveal / pairing gates answer
 * step_up_required, and the extension polls until the window reopens).
 *
 * Before this page existed the extension sent the user to the portal root,
 * which just rendered the app list: nothing there could refresh the portal
 * session's step-up stamp, so the only way to auto-fill again was to sign out
 * and back in. Verifying here re-stamps the session and the extension's poll
 * picks it up within seconds.
 */
export default function StepUpPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [done, setDone] = useState(false)

  return (
    <div className="flex min-h-screen items-center justify-center bg-canvas p-4">
      <div className="w-full max-w-md rounded-2xl border border-border bg-surface p-6 shadow-xl">
        <div className="mb-4 flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10 text-primary">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-ink">
              {done ? t('stepup.pageDoneTitle') : t('stepup.pageTitle')}
            </h1>
            <p className="text-sm text-muted">
              {done ? t('stepup.pageDoneHint') : t('stepup.pageHint')}
            </p>
          </div>
        </div>

        {done ? (
          <Button className="w-full" onClick={() => navigate('/apps', { replace: true })}>
            {t('stepup.backToApps')}
          </Button>
        ) : (
          <StepUpPrompt onVerified={() => setDone(true)} />
        )}
      </div>
    </div>
  )
}
