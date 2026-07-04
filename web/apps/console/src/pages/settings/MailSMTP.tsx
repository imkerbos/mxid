// MailSMTP — admin form for outgoing email server config.
//
// Two notable behaviors:
//
//   1. Password field shows a placeholder ("●●● 已设置") when the backend
//      reports password_set=true but withholds the actual value. Leaving
//      it empty on save preserves the existing password; typing replaces.
//
//   2. "测试发送" sends a probe email to the admin's typed address using
//      the CURRENT SAVED config — not the unsaved form values — so admins
//      must save before testing. We show a hint when the form is dirty.
import { useEffect, useState } from 'react'
import { Save, Send, Loader2 } from 'lucide-react'
import { settingsApi, useTranslation } from '@mxid/shared'
import type { MailSMTP } from '@mxid/shared'
import { Field, Input, Select, Button } from '../../components/ui'
import { toast } from '../../components/ui/toast'

const TLS_OPTION_KEYS = [
  { v: 'starttls', k: 'settings.smtp.tlsStartTLS' },
  { v: 'tls', k: 'settings.smtp.tlsTLS' },
  { v: 'none', k: 'settings.smtp.tlsNone' },
] as const

export default function MailSMTPPage() {
  const { t } = useTranslation()
  const PWD_PLACEHOLDER = t('settings.smtp.passwordPlaceholderSet')
  const [cfg, setCfg] = useState<MailSMTP>({
    enabled: false,
    host: '',
    port: 587,
    username: '',
    password: '',
    from_address: '',
    from_name: 'MXID',
    tls_mode: 'starttls',
    skip_verify: false,
  })
  const [passwordSet, setPasswordSet] = useState(false)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [dirty, setDirty] = useState(false)
  const [testTo, setTestTo] = useState('')

  useEffect(() => {
    settingsApi
      .getMailSMTP()
      .then((d) => {
        setCfg(d.config)
        setPasswordSet(d.password_set)
      })
      .catch(() => toast.error(t('settings.smtp.loadFailed')))
      .finally(() => setLoading(false))
  }, [])

  const update = (patch: Partial<MailSMTP>) => {
    setCfg((c) => ({ ...c, ...patch }))
    setDirty(true)
  }

  const handleSave = async () => {
    setSaving(true)
    try {
      await settingsApi.putMailSMTP(cfg)
      toast.success(t('settings.smtp.saved'))
      setDirty(false)
      if (cfg.password) setPasswordSet(true)
      setCfg((c) => ({ ...c, password: '' })) // clear after save
    } catch (e) {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message
      toast.error(t("common.failed"), msg)
    } finally {
      setSaving(false)
    }
  }

  const handleTest = async () => {
    if (!testTo) {
      toast.warning(t('settings.smtp.testToRequired'))
      return
    }
    setTesting(true)
    try {
      await settingsApi.testMailSMTP(testTo)
      toast.success(t('settings.smtp.testSent'), t('settings.smtp.testSentHint', { to: testTo }))
    } catch (e) {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message
      toast.error(t('settings.smtp.testFailed'), msg)
    } finally {
      setTesting(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-32">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* ─── Card: SMTP 服务器 ─── */}
      <section className="rounded-xl border border-border bg-surface p-6">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-ink">{t('settings.smtp.title')}</h2>
            <p className="mt-0.5 text-sm text-muted">
              {t('settings.smtp.desc')}
            </p>
          </div>
          <label className="flex items-center gap-2 text-sm text-ink">
            <input
              type="checkbox"
              checked={cfg.enabled}
              onChange={(e) => update({ enabled: e.target.checked })}
              className="h-4 w-4 rounded border-border"
            />
            {t('common.enable')}
          </label>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <Field label={`${t('settings.smtp.host')} *`} hint={t('settings.smtp.hostHint')}>
            <Input
              value={cfg.host}
              onChange={(e) => update({ host: e.target.value })}
              placeholder="smtp.example.com"
            />
          </Field>
          <Field label={`${t('settings.smtp.port')} *`}>
            <Input
              type="number"
              value={cfg.port}
              onChange={(e) => update({ port: Number(e.target.value) || 0 })}
              placeholder="587"
            />
          </Field>
          <Field label={t('settings.smtp.tlsMode')}>
            <Select value={cfg.tls_mode} onChange={(e) => update({ tls_mode: e.target.value as MailSMTP['tls_mode'] })}>
              {TLS_OPTION_KEYS.map((o) => (
                <option key={o.v} value={o.v}>{t(o.k)}</option>
              ))}
            </Select>
          </Field>
          <Field label="" hint="">
            <label className="flex items-center gap-2 pt-7 text-sm text-ink">
              <input
                type="checkbox"
                checked={cfg.skip_verify}
                onChange={(e) => update({ skip_verify: e.target.checked })}
                className="h-4 w-4 rounded border-border"
              />
              {t('settings.smtp.skipVerify')}
            </label>
          </Field>
          <Field label={t('settings.smtp.username')}>
            <Input
              value={cfg.username}
              onChange={(e) => update({ username: e.target.value })}
              placeholder="user@example.com"
            />
          </Field>
          <Field label={t('settings.smtp.password')} hint={passwordSet && !cfg.password ? t('settings.smtp.passwordHint') : ''}>
            <Input
              type="password"
              value={cfg.password}
              onChange={(e) => update({ password: e.target.value })}
              placeholder={passwordSet ? PWD_PLACEHOLDER : t('settings.smtp.passwordPlaceholderNew')}
              autoComplete="new-password"
            />
          </Field>
          <Field label={`${t('settings.smtp.fromAddress')} *`}>
            <Input
              type="email"
              value={cfg.from_address}
              onChange={(e) => update({ from_address: e.target.value })}
              placeholder="noreply@example.com"
            />
          </Field>
          <Field label={t('settings.smtp.fromName')}>
            <Input
              value={cfg.from_name}
              onChange={(e) => update({ from_name: e.target.value })}
              placeholder="MXID"
            />
          </Field>
        </div>

        <div className="mt-6 flex justify-end gap-2">
          <Button onClick={handleSave} loading={saving} icon={<Save className="h-4 w-4" />}>
            {saving ? t('common.saving') : t('settings.smtp.saveConfig')}
          </Button>
        </div>
      </section>

      {/* ─── Card: 测试发送 ─── */}
      <section className="rounded-xl border border-border bg-surface p-6">
        <div className="mb-4">
          <h2 className="text-lg font-semibold text-ink">{t('settings.smtp.testTitle')}</h2>
          <p className="mt-0.5 text-sm text-muted">
            {t('settings.smtp.testDesc')}
          </p>
        </div>
        {dirty && (
          <div className="mb-3 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
            {t('settings.smtp.dirtyWarn')}
          </div>
        )}
        <div className="flex gap-2">
          <Input
            type="email"
            value={testTo}
            onChange={(e) => setTestTo(e.target.value)}
            placeholder={t('settings.smtp.testToPlaceholder')}
            className="flex-1"
          />
          <Button
            onClick={handleTest}
            loading={testing}
            disabled={testing || !cfg.enabled}
            title={!cfg.enabled ? t('settings.smtp.mustEnableFirst') : ''}
            icon={<Send className="h-4 w-4" />}
            variant="ghost"
            className="border border-primary/30 bg-primary/5 text-primary hover:bg-primary/10 hover:text-primary"
          >
            {testing ? t('settings.smtp.testing') : t('settings.smtp.sendTest')}
          </Button>
        </div>
      </section>
    </div>
  )
}
