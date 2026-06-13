// External IdP / 身份源管理页。
//
// Admin 在这里配置 Lark / Feishu / GitHub / DingTalk / ... 的 OAuth 凭证。
// 保存后 portal 登录页会自动出现「使用 Lark 登录」等按钮。
import { useCallback, useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Plus, Pencil, Trash2, X, Plug, Power } from 'lucide-react'
import { externalIdpApi, cn, useTranslation } from '@mxid/shared'
import type { ExternalIDP } from '@mxid/shared'
import PageHeader from '../../components/layout/PageHeader'
import { Field, Button, Tag, EmptyState, LoadingState, pageMotion } from '../../components/ui'
import { toast, extractMessage } from '../../components/ui/toast'

// Provider field schemas — what the config form renders per type. Keep this
// in lock-step with the Go provider implementations (providers/*.go).
type Field = { key: string; label: string; placeholder?: string; secret?: boolean; required?: boolean; hint?: string }

function useProviderFields(): Record<string, Field[]> {
  const { t } = useTranslation()
  return {
    lark: [
      { key: 'app_id', label: 'App ID', placeholder: 'cli_xxxxxxxxxxxxxxxx', required: true, hint: t('idps.providerHints.larkAppId') },
      { key: 'app_secret', label: 'App Secret', secret: true, required: true, hint: t('idps.providerHints.larkAppSecret') },
    ],
    feishu: [
      { key: 'app_id', label: 'App ID', placeholder: 'cli_xxxxxxxxxxxxxxxx', required: true, hint: t('idps.providerHints.feishuAppId') },
      { key: 'app_secret', label: 'App Secret', secret: true, required: true },
    ],
    teams: [
      { key: 'client_id', label: 'Application (client) ID', required: true, hint: t('idps.providerHints.teamsClientId') },
      { key: 'client_secret', label: 'Client Secret', secret: true, required: true, hint: t('idps.providerHints.teamsClientSecret') },
      { key: 'tenant', label: 'Tenant', placeholder: 'common', hint: t('idps.providerHints.teamsTenant') },
      { key: 'scopes', label: 'Scopes', placeholder: 'openid profile email User.Read', hint: t('idps.providerHints.teamsScopes') },
    ],
  }
}

function useProviderLabel() {
  const { t } = useTranslation()
  const labels: Record<string, string> = {
    lark: t('idps.providerLabels.lark'),
    feishu: t('idps.providerLabels.feishu'),
    teams: t('idps.providerLabels.teams'),
  }
  return labels
}

export default function IDPsPage() {
  const { t } = useTranslation()
  const PROVIDER_LABEL = useProviderLabel()
  const [items, setItems] = useState<ExternalIDP[]>([])
  const [types, setTypes] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [editing, setEditing] = useState<ExternalIDP | null>(null)
  const [showForm, setShowForm] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [list, typeList] = await Promise.all([externalIdpApi.list(), externalIdpApi.types()])
      setItems(list ?? [])
      setTypes(typeList ?? [])
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const openCreate = () => {
    setEditing(null)
    setShowForm(true)
  }
  const openEdit = (idp: ExternalIDP) => {
    setEditing(idp)
    setShowForm(true)
  }
  const remove = async (idp: ExternalIDP) => {
    if (!confirm(t('idps.confirmDelete', { name: idp.name }))) return
    try {
      await externalIdpApi.delete(idp.id)
      toast.success(t('common.deleteSuccess'))
      await load()
    } catch (e) {
      toast.error(t('common.deleteFailed'), extractMessage(e))
    }
  }
  const toggleStatus = async (idp: ExternalIDP) => {
    try {
      await externalIdpApi.update(idp.id, { status: idp.status === 1 ? 2 : 1 })
      toast.success(t('common.saveSuccess'))
      await load()
    } catch (e) {
      toast.error(t('common.saveFailed'), extractMessage(e))
    }
  }

  return (
    <motion.div {...pageMotion}>
      <PageHeader
        title={t('idps.title')}
        description={t('idps.subtitle')}
        actions={
          <Button onClick={openCreate} icon={<Plus className="h-4 w-4" />}>
            {t('idps.addBtn')}
          </Button>
        }
      />

      <div className="rounded-xl border border-gray-100 bg-white shadow-sm">
        {loading ? (
          <LoadingState />
        ) : items.length === 0 ? (
          <EmptyState>{t('idps.empty')}</EmptyState>
        ) : (
          <div className="divide-y divide-gray-50">
            {items.map((idp) => (
              <div key={idp.id} className="flex items-center justify-between p-5 hover:bg-gray-50/50">
                <div className="flex min-w-0 items-center gap-4">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                    {idp.icon ? <img src={idp.icon} alt="" className="h-6 w-6" /> : <Plug className="h-5 w-5" />}
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-gray-900">{idp.name}</span>
                      <Tag variant="blue">{PROVIDER_LABEL[idp.type] ?? idp.type}</Tag>
                      {idp.status === 1 ? (
                        <Tag variant="green">{t('common.enabled')}</Tag>
                      ) : (
                        <Tag variant="gray">{t('common.disabled')}</Tag>
                      )}
                      {idp.auto_create && <Tag variant="amber">{t('idps.autoCreateTag')}</Tag>}
                    </div>
                    <p className="mt-0.5 text-xs text-gray-500">
                      <code className="rounded bg-gray-100 px-1.5 py-0.5">{idp.code}</code>
                      {idp.description ? ` · ${idp.description}` : ''}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    variant={idp.status === 1 ? 'secondary' : 'success'}
                    onClick={() => toggleStatus(idp)}
                    icon={<Power className="h-3.5 w-3.5" />}
                  >
                    {idp.status === 1 ? t('common.disable') : t('common.enable')}
                  </Button>
                  <Button size="sm" variant="secondary" onClick={() => openEdit(idp)} icon={<Pencil className="h-3.5 w-3.5" />}>
                    {t('common.edit')}
                  </Button>
                  <Button size="sm" variant="danger" onClick={() => remove(idp)} icon={<Trash2 className="h-3.5 w-3.5" />}>
                    {t('common.delete')}
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <AnimatePresence>
        {showForm && (
          <IDPForm
            initial={editing}
            allowedTypes={types}
            onCancel={() => setShowForm(false)}
            onSaved={async () => {
              setShowForm(false)
              await load()
            }}
          />
        )}
      </AnimatePresence>
    </motion.div>
  )
}

/* ──────────────────────── form ──────────────────────── */

interface FormState {
  type: string
  name: string
  code: string
  description: string
  icon: string
  auto_create: boolean
  status: number
  sort_order: number
  config: Record<string, string>
}

function emptyForm(): FormState {
  return {
    type: 'lark',
    name: '',
    code: '',
    description: '',
    icon: '',
    auto_create: true,
    status: 1,
    sort_order: 0,
    config: {},
  }
}

function IDPForm({
  initial,
  allowedTypes,
  onCancel,
  onSaved,
}: {
  initial: ExternalIDP | null
  allowedTypes: string[]
  onCancel: () => void
  onSaved: () => Promise<void> | void
}) {
  const { t } = useTranslation()
  const PROVIDER_LABEL = useProviderLabel()
  const PROVIDER_FIELDS = useProviderFields()
  const [form, setForm] = useState<FormState>(() => {
    if (!initial) return emptyForm()
    return {
      type: initial.type,
      name: initial.name,
      code: initial.code,
      description: initial.description ?? '',
      icon: initial.icon ?? '',
      auto_create: initial.auto_create,
      status: initial.status,
      sort_order: initial.sort_order,
      config: Object.fromEntries(
        Object.entries(initial.config ?? {}).map(([k, v]) => [k, typeof v === 'string' ? v : JSON.stringify(v)]),
      ),
    }
  })
  const [saving, setSaving] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const fields = PROVIDER_FIELDS[form.type] ?? []

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setErr(null)

    // Coerce scope strings ("a b c") into arrays before submitting.
    const cfg: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(form.config)) {
      if (k === 'scopes' && v.trim()) {
        cfg[k] = v.split(/\s+/).filter(Boolean)
      } else {
        cfg[k] = v
      }
    }

    setSaving(true)
    try {
      if (initial) {
        await externalIdpApi.update(initial.id, {
          name: form.name,
          description: form.description || undefined,
          icon: form.icon || undefined,
          config: cfg,
          status: form.status,
          auto_create: form.auto_create,
          sort_order: form.sort_order,
        })
      } else {
        await externalIdpApi.create({
          type: form.type,
          name: form.name,
          code: form.code,
          description: form.description || undefined,
          icon: form.icon || undefined,
          config: cfg,
          auto_create: form.auto_create,
          sort_order: form.sort_order,
        })
      }
      toast.success(t('common.saveSuccess'))
      await onSaved()
    } catch (e) {
      const msg = extractMessage(e, t('idps.saveFailed'))
      setErr(msg)
      toast.error(t('common.saveFailed'), msg)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        className="w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-xl bg-white p-6 shadow-xl"
      >
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-lg font-semibold">{initial ? t('idps.editTitle') : t('idps.createTitle')}</h3>
          <button onClick={onCancel} className="rounded p-1 text-gray-400 hover:bg-gray-100"><X className="h-4 w-4" /></button>
        </div>

        <form onSubmit={submit} className="space-y-4">
          <Field label={t('idps.fields.providerType')} hint={t('idps.fields.providerTypeHint')}>
            <select
              value={form.type}
              onChange={(e) => setForm({ ...form, type: e.target.value, config: {} })}
              disabled={!!initial}
              className={cn('w-full rounded-lg border px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20', initial ? 'border-gray-200 bg-gray-50 text-gray-500' : 'border-gray-300')}
            >
              {allowedTypes.map((tp) => (
                <option key={tp} value={tp}>{PROVIDER_LABEL[tp] ?? tp}</option>
              ))}
            </select>
          </Field>

          <div className="grid grid-cols-2 gap-4">
            <Field label={t('idps.fields.nameRequired')} hint={t('idps.fields.nameHint')}>
              <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20" />
            </Field>
            <Field label={initial ? t('idps.fields.codeImmutable') : t('idps.fields.codeRequired')} hint={t('idps.fields.codeHint')}>
              <input
                value={form.code}
                onChange={(e) => setForm({ ...form, code: e.target.value })}
                disabled={!!initial}
                required={!initial}
                className={cn('w-full rounded-lg border px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20', initial ? 'border-gray-200 bg-gray-50 text-gray-500' : 'border-gray-300')}
              />
            </Field>
          </div>

          <Field label={t('idps.fields.description')}>
            <input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20" />
          </Field>

          <Field label={t('idps.fields.iconUrl')}>
            <input value={form.icon} onChange={(e) => setForm({ ...form, icon: e.target.value })} placeholder="https://..." className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20" />
          </Field>

          {/* Provider-specific config block */}
          {fields.length > 0 && (
            <div className="rounded-lg border border-gray-200 bg-gray-50 p-3">
              <p className="mb-3 text-xs font-medium text-gray-600">{t('idps.fields.credentials', { provider: PROVIDER_LABEL[form.type] ?? form.type })}</p>
              <div className="space-y-3">
                {fields.map((f) => (
                  <Field key={f.key} label={f.required ? `${f.label} *` : f.label} hint={f.hint}>
                    <input
                      type={f.secret ? 'password' : 'text'}
                      value={form.config[f.key] ?? ''}
                      onChange={(e) => setForm({ ...form, config: { ...form.config, [f.key]: e.target.value } })}
                      placeholder={f.placeholder}
                      required={f.required && !initial}
                      className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                    />
                  </Field>
                ))}
              </div>
            </div>
          )}

          <div className="grid grid-cols-2 gap-4">
            <Field label={t('idps.fields.enable')}>
              <select value={form.status} onChange={(e) => setForm({ ...form, status: Number(e.target.value) })} className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20">
                <option value={1}>{t('common.enable')}</option>
                <option value={2}>{t('common.disable')}</option>
              </select>
            </Field>
            <Field label={t('idps.fields.sortOrder')} hint={t('idps.fields.sortOrderHint')}>
              <input type="number" value={form.sort_order} onChange={(e) => setForm({ ...form, sort_order: Number(e.target.value) })} className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20" />
            </Field>
          </div>

          <label className="flex items-start gap-2 text-sm">
            <input type="checkbox" checked={form.auto_create} onChange={(e) => setForm({ ...form, auto_create: e.target.checked })} className="mt-0.5 h-4 w-4 rounded border-gray-300 text-primary" />
            <span>
              <span className="font-medium">{t('idps.fields.autoCreate')}</span>
              <span className="ml-1 text-xs text-gray-500">{t('idps.fields.autoCreateHint')}</span>
            </span>
          </label>

          {err && <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{err}</div>}

          <div className="flex justify-end gap-3 pt-2">
            <Button type="button" variant="secondary" onClick={onCancel}>{t('common.cancel')}</Button>
            <Button type="submit" loading={saving}>
              {initial ? t('common.save') : t('common.create')}
            </Button>
          </div>
        </form>
      </motion.div>
    </div>
  )
}

