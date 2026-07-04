// NoAccess — landing page when OIDC /authorize rejected the user due to
// app access policy. Reached via redirect from backend; query params
// carry the app code and a machine-readable reason.
import { useSearchParams, Link } from 'react-router-dom'
import { ShieldX } from 'lucide-react'
import { useTranslation } from '@mxid/shared'

export default function NoAccessPage() {
  const { t } = useTranslation()
  const [params] = useSearchParams()
  const app = params.get('app') || ''
  const reason = params.get('reason') || 'no-rule-matched'
  const friendly = t('portal.noAccess.hint')

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-md rounded-2xl border border-border bg-surface p-8 text-center shadow-sm">
        <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-red-100">
          <ShieldX className="h-7 w-7 text-red-600" />
        </div>
        <h1 className="text-xl font-semibold text-ink">{t('portal.noAccess.title')} {app}</h1>
        <p className="mt-2 text-sm text-muted">{friendly}</p>
        <div className="mt-2 inline-block rounded-md bg-surface-muted px-2 py-1 font-mono text-xs text-faint">
          reason: {reason}
        </div>
        <div className="mt-6">
          <Link
            to="/"
            className="inline-flex items-center rounded-lg bg-primary px-4 py-2 text-sm font-medium text-white hover:bg-primary-hover"
          >
            {t('portal.noAccess.back')}
          </Link>
        </div>
        <p className="mt-4 text-xs text-faint">
          {t('portal.noAccess.contactHint')}
        </p>
      </div>
    </div>
  )
}
