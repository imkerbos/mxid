// System version page — shows the running MXID build and lets a super_admin
// check whether a newer release exists. Read-only: it never downloads or
// applies an update (applying an upgrade to a running IAM is a deliberate
// non-goal). Backend: GET/POST /console/system/version.
import { useEffect, useState } from 'react'
import { Loader2, RefreshCw, CheckCircle2, AlertTriangle, ArrowUpCircle, ExternalLink } from 'lucide-react'
import { systemApi, useTranslation } from '@mxid/shared'
import type { VersionStatus } from '@mxid/shared'
import { Button } from '../../components/ui'
import { toast } from '../../components/ui/toast'

function fmt(ts?: string): string {
  if (!ts) return ''
  const d = new Date(ts)
  return isNaN(d.getTime()) ? ts : d.toLocaleString()
}

export default function SystemVersionPage() {
  const { t } = useTranslation()
  const [status, setStatus] = useState<VersionStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [checking, setChecking] = useState(false)

  useEffect(() => {
    systemApi
      .versionStatus()
      .then(setStatus)
      .catch(() => toast.error(t('settings.systemVersion.loadFailed')))
      .finally(() => setLoading(false))
  }, [])

  const check = async () => {
    setChecking(true)
    try {
      const s = await systemApi.checkUpdate()
      setStatus(s)
      if (s.error) {
        toast.error(t('settings.systemVersion.checkFailed'), s.error)
      } else if (s.update_available) {
        toast.success(t('settings.systemVersion.updateAvailable'))
      } else {
        toast.success(t('settings.systemVersion.upToDate'))
      }
    } catch (e) {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message
      toast.error(t('settings.systemVersion.checkFailed'), msg)
    } finally {
      setChecking(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20 text-faint">
        <Loader2 className="h-5 w-5 animate-spin" />
      </div>
    )
  }

  const cur = status?.current
  const latest = status?.latest
  const updateAvailable = status?.update_available

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-ink">{t('settings.systemVersion.title')}</h2>
        <p className="mt-1 text-sm text-muted">{t('settings.systemVersion.desc')}</p>
      </div>

      {/* Current build */}
      <div className="rounded-xl border border-border bg-surface p-5">
        <dl className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <div>
            <dt className="text-xs font-medium uppercase tracking-wide text-faint">
              {t('settings.systemVersion.current')}
            </dt>
            <dd className="mt-1 font-mono text-sm text-ink">{cur?.version || '—'}</dd>
          </div>
          <div>
            <dt className="text-xs font-medium uppercase tracking-wide text-faint">
              {t('settings.systemVersion.commit')}
            </dt>
            <dd className="mt-1 font-mono text-sm text-ink">{cur?.commit || '—'}</dd>
          </div>
          <div>
            <dt className="text-xs font-medium uppercase tracking-wide text-faint">
              {t('settings.systemVersion.buildTime')}
            </dt>
            <dd className="mt-1 font-mono text-sm text-ink">{fmt(cur?.build_time) || '—'}</dd>
          </div>
        </dl>
      </div>

      {/* Update status */}
      <div className="rounded-xl border border-border bg-surface p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            {status?.error ? (
              <>
                <AlertTriangle className="h-5 w-5 text-amber-500" />
                <span className="text-sm text-ink">{status.error}</span>
              </>
            ) : updateAvailable ? (
              <>
                <ArrowUpCircle className="h-5 w-5 text-primary" />
                <span className="text-sm font-medium text-primary">
                  {t('settings.systemVersion.updateAvailable')}
                  {latest?.version ? ` — ${latest.version}` : ''}
                </span>
              </>
            ) : (
              <>
                <CheckCircle2 className="h-5 w-5 text-emerald-500" />
                <span className="text-sm text-ink">{t('settings.systemVersion.upToDate')}</span>
              </>
            )}
          </div>

          <Button onClick={check} disabled={checking} variant="secondary">
            {checking ? (
              <Loader2 className="mr-1.5 h-4 w-4 animate-spin" />
            ) : (
              <RefreshCw className="mr-1.5 h-4 w-4" />
            )}
            {checking ? t('settings.systemVersion.checking') : t('settings.systemVersion.checkNow')}
          </Button>
        </div>

        {(latest || status?.checked_at) && (
          <div className="mt-4 space-y-1 border-t border-border pt-4 text-sm text-muted">
            {latest?.version && (
              <div className="flex items-center gap-2">
                <span>{t('settings.systemVersion.latest')}:</span>
                <span className="font-mono text-ink">{latest.version}</span>
                {latest.url && (
                  <a
                    href={latest.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-primary hover:underline"
                  >
                    {t('settings.systemVersion.viewRelease')}
                    <ExternalLink className="h-3.5 w-3.5" />
                  </a>
                )}
              </div>
            )}
            <div>
              {t('settings.systemVersion.lastChecked')}:{' '}
              {status?.checked_at ? fmt(status.checked_at) : t('settings.systemVersion.never')}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
