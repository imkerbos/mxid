// Security policy form — password rules + lockout + session.
//
// Old defaults lived in config.yaml; they migrate to DB the first time
// admin saves. Backend reads via setting.Service.SecurityPolicy(ctx, tid)
// with fallback to DefaultSecurityPolicy when no row exists.
import { useEffect, useState } from 'react'
import { Loader2, Save } from 'lucide-react'
import { settingsApi, useTranslation } from '@mxid/shared'
import type { SecurityPolicy } from '@mxid/shared'
import { Field, Input, Button } from '../../components/ui'
import { toast } from '../../components/ui/toast'

export default function SecurityPage() {
  const { t } = useTranslation()
  const [v, setV] = useState<SecurityPolicy | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    settingsApi
      .getSecurity()
      .then(setV)
      .catch(() => toast.error(t('settings.security.loadFailed')))
      .finally(() => setLoading(false))
  }, [])

  const save = async () => {
    if (!v) return
    setSaving(true)
    try {
      await settingsApi.putSecurity(v)
      toast.success(t('settings.security.saved'))
    } catch (e) {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message
      toast.error(t("common.failed"), msg)
    } finally {
      setSaving(false)
    }
  }

  if (loading || !v) {
    return (
      <div className="flex items-center justify-center py-32">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <Section title={t('settings.security.passwordTitle')} desc={t('settings.security.passwordDesc')}>
        <div className="grid grid-cols-2 gap-4 md:grid-cols-3">
          <Field label={t('settings.security.minLength')}>
            <Input
              type="number"
              value={v.password.min_length}
              onChange={(e) =>
                setV({ ...v, password: { ...v.password, min_length: Number(e.target.value) } })
              }
            />
          </Field>
          <Field label={t('settings.security.historyCount')}>
            <Input
              type="number"
              value={v.password.history_count}
              onChange={(e) =>
                setV({ ...v, password: { ...v.password, history_count: Number(e.target.value) } })
              }
            />
          </Field>
          <Field label={t('settings.security.expireDays')}>
            <Input
              type="number"
              value={v.password.expire_days}
              onChange={(e) =>
                setV({ ...v, password: { ...v.password, expire_days: Number(e.target.value) } })
              }
            />
          </Field>
        </div>
        <div className="mt-3 flex flex-wrap gap-4">
          <Toggle
            label={t('settings.security.requireUpper')}
            checked={v.password.require_uppercase}
            onChange={(b) => setV({ ...v, password: { ...v.password, require_uppercase: b } })}
          />
          <Toggle
            label={t('settings.security.requireLower')}
            checked={v.password.require_lowercase}
            onChange={(b) => setV({ ...v, password: { ...v.password, require_lowercase: b } })}
          />
          <Toggle
            label={t('settings.security.requireNumber')}
            checked={v.password.require_number}
            onChange={(b) => setV({ ...v, password: { ...v.password, require_number: b } })}
          />
          <Toggle
            label={t('settings.security.requireSpecial')}
            checked={v.password.require_special}
            onChange={(b) => setV({ ...v, password: { ...v.password, require_special: b } })}
          />
        </div>
      </Section>

      <Section title={t('settings.security.loginTitle')} desc={t('settings.security.loginDesc')}>
        <div className="grid grid-cols-2 gap-4 md:grid-cols-3">
          <Field label={t('settings.security.maxFailed')}>
            <Input
              type="number"
              value={v.login.max_failed_attempts}
              onChange={(e) =>
                setV({ ...v, login: { ...v.login, max_failed_attempts: Number(e.target.value) } })
              }
            />
          </Field>
          <Field label={t('settings.security.lockoutMin')}>
            <Input
              type="number"
              value={v.login.lockout_minutes}
              onChange={(e) =>
                setV({ ...v, login: { ...v.login, lockout_minutes: Number(e.target.value) } })
              }
            />
          </Field>
          <Field label={t('settings.security.captchaAfter')}>
            <Input
              type="number"
              value={v.login.captcha_after_failures}
              onChange={(e) =>
                setV({ ...v, login: { ...v.login, captcha_after_failures: Number(e.target.value) } })
              }
            />
          </Field>
        </div>
      </Section>

      <Section title={t('settings.security.sessionTitle')} desc={t('settings.security.sessionDesc')}>
        <div className="grid grid-cols-2 gap-4 md:grid-cols-3">
          <Field label={t('settings.security.idleMin')}>
            <Input
              type="number"
              value={v.session.idle_minutes}
              onChange={(e) =>
                setV({ ...v, session: { ...v.session, idle_minutes: Number(e.target.value) } })
              }
            />
          </Field>
          <Field label={t('settings.security.absoluteHour')}>
            <Input
              type="number"
              value={v.session.absolute_hours}
              onChange={(e) =>
                setV({ ...v, session: { ...v.session, absolute_hours: Number(e.target.value) } })
              }
            />
          </Field>
          <Field label={t('settings.security.rememberHour')}>
            <Input
              type="number"
              value={v.session.remember_me_hours}
              onChange={(e) =>
                setV({ ...v, session: { ...v.session, remember_me_hours: Number(e.target.value) } })
              }
            />
          </Field>
        </div>
      </Section>

      <Section title={t('settings.security.rateLimitTitle')} desc={t('settings.security.rateLimitDesc')}>
        <div className="grid grid-cols-2 gap-4 md:grid-cols-3">
          <Field label={t('settings.security.perUserPerMinute')} hint={t('settings.security.perUserPerMinuteHint')}>
            <Input
              type="number"
              value={v.rate_limit.per_user_per_minute}
              onChange={(e) =>
                setV({ ...v, rate_limit: { ...v.rate_limit, per_user_per_minute: Number(e.target.value) } })
              }
            />
          </Field>
        </div>
      </Section>

      <div className="flex justify-end">
        <Button onClick={save} loading={saving} icon={<Save className="h-4 w-4" />}>
          {saving ? t('common.saving') : t('settings.security.saveBtn')}
        </Button>
      </div>
    </div>
  )
}

function Section({ title, desc, children }: { title: string; desc?: string; children: React.ReactNode }) {
  return (
    <section className="rounded-xl border border-border bg-surface p-6">
      <div className="mb-4">
        <h2 className="text-lg font-semibold text-ink">{title}</h2>
        {desc && <p className="mt-0.5 text-sm text-muted">{desc}</p>}
      </div>
      {children}
    </section>
  )
}

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (b: boolean) => void }) {
  return (
    <label className="flex items-center gap-2 text-sm text-ink">
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} className="h-4 w-4 rounded border-border" />
      {label}
    </label>
  )
}
