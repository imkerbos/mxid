// Tenant 管理页 — super_admin only.
//
// 普通 tenant_admin 调 GET /tenants 仍能拿自己 row（用于左上角 switcher），
// 但 POST/PUT/DELETE 被 authz.Require("tenant.manage") 拒绝。后端 503/403。
import { useCallback, useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Plus, Pencil, Trash2, Loader2, X, Building } from 'lucide-react'
import { tenantApi, cn, useTranslation } from '@mxid/shared'
import type { Tenant } from '@mxid/shared'
import PageHeader from '../../components/layout/PageHeader'
import { Field, Input } from '../../components/ui'

export default function TenantsPage() {
  const { t } = useTranslation()
  const [items, setItems] = useState<Tenant[]>([])
  const [loading, setLoading] = useState(true)
  const [editing, setEditing] = useState<Tenant | null>(null)
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ name: '', code: '', status: 1 })
  const [saving, setSaving] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const list = await tenantApi.list()
      setItems(list ?? [])
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const openCreate = () => {
    setEditing(null)
    setForm({ name: '', code: '', status: 1 })
    setShowForm(true)
  }
  const openEdit = (tenant: Tenant) => {
    setEditing(tenant)
    setForm({ name: tenant.name, code: tenant.code, status: tenant.status })
    setShowForm(true)
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    try {
      if (editing) {
        await tenantApi.update(editing.id, { name: form.name, status: form.status })
      } else {
        await tenantApi.create({ name: form.name, code: form.code, status: form.status })
      }
      setShowForm(false)
      await load()
    } finally {
      setSaving(false)
    }
  }

  const remove = async (tenant: Tenant) => {
    if (!confirm(t('tenants.confirmDelete', { name: tenant.name }))) return
    try {
      await tenantApi.delete(tenant.id)
      await load()
    } catch (e) {
      alert(t('tenants.deleteFailed', { msg: (e as Error).message }))
    }
  }

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.3 }}>
      <PageHeader
        title={t('tenants.title')}
        description={t('tenants.subtitle')}
        actions={
          <button
            onClick={openCreate}
            className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-white hover:bg-primary-hover"
          >
            <Plus className="h-4 w-4" />
            {t('tenants.create')}
          </button>
        }
      />

      <div className="rounded-xl border border-gray-100 bg-white shadow-sm">
        {loading ? (
          <div className="py-16 text-center text-sm text-gray-400">
            <Loader2 className="mx-auto h-5 w-5 animate-spin" />
          </div>
        ) : items.length === 0 ? (
          <div className="py-16 text-center text-sm text-gray-400">{t('tenants.empty')}</div>
        ) : (
          <div className="divide-y divide-gray-50">
            {items.map((tenant) => (
              <div key={tenant.id} className="flex items-center justify-between p-5 hover:bg-gray-50/50">
                <div className="flex items-center gap-4">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
                    <Building className="h-5 w-5" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-gray-900">{tenant.name}</span>
                      <code className="rounded bg-gray-100 px-1.5 py-0.5 text-xs text-gray-500">{tenant.code}</code>
                      {tenant.status === 1 ? (
                        <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-xs text-emerald-700">{t('common.enabled')}</span>
                      ) : (
                        <span className="rounded-full bg-gray-200 px-2 py-0.5 text-xs text-gray-600">{t('common.disabled')}</span>
                      )}
                      {String(tenant.id) === '1' && (
                        <span className="rounded-full bg-amber-100 px-2 py-0.5 text-xs text-amber-700">{t('tenants.defaultTag')}</span>
                      )}
                    </div>
                    <p className="mt-0.5 text-xs text-gray-400">id: {tenant.id}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button onClick={() => openEdit(tenant)} className="inline-flex items-center gap-1 rounded-lg border border-gray-200 px-2.5 py-1 text-xs hover:bg-gray-50">
                    <Pencil className="h-3.5 w-3.5" /> {t('common.edit')}
                  </button>
                  {String(tenant.id) !== '1' && (
                    <button onClick={() => remove(tenant)} className="inline-flex items-center gap-1 rounded-lg border border-red-200 bg-red-50 px-2.5 py-1 text-xs text-red-600 hover:bg-red-100">
                      <Trash2 className="h-3.5 w-3.5" /> {t('common.delete')}
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <AnimatePresence>
        {showForm && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-md rounded-xl bg-white p-6 shadow-xl"
            >
              <div className="mb-4 flex items-center justify-between">
                <h3 className="text-lg font-semibold">{editing ? t('tenants.editTitle') : t('tenants.createTitle')}</h3>
                <button onClick={() => setShowForm(false)} className="rounded p-1 text-gray-400 hover:bg-gray-100"><X className="h-4 w-4" /></button>
              </div>
              <form onSubmit={submit} className="space-y-4">
                <Field label={t('tenants.fields.name')} required>
                  <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
                </Field>
                <Field label={editing ? t('tenants.fields.codeImmutable') : t('tenants.fields.code')} required={!editing} hint={t('tenants.fields.codeHint')}>
                  <Input
                    value={form.code}
                    onChange={(e) => setForm({ ...form, code: e.target.value })}
                    disabled={!!editing}
                    required={!editing}
                    className={cn(editing ? 'bg-gray-50 text-gray-500' : '')}
                  />
                </Field>
                <Field label={t('tenants.fields.status')}>
                  <select value={form.status} onChange={(e) => setForm({ ...form, status: Number(e.target.value) })} className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20">
                    <option value={1}>{t('common.enable')}</option>
                    <option value={2}>{t('common.disable')}</option>
                  </select>
                </Field>
                <div className="flex justify-end gap-3 pt-2">
                  <button type="button" onClick={() => setShowForm(false)} className="rounded-lg border border-gray-200 px-4 py-2 text-sm hover:bg-gray-50">{t('common.cancel')}</button>
                  <button type="submit" disabled={saving} className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-60">
                    {saving && <Loader2 className="h-4 w-4 animate-spin" />}
                    {editing ? t('common.save') : t('common.create')}
                  </button>
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}
