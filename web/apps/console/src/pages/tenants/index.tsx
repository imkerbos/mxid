// Tenant 管理页 — super_admin only.
//
// 普通 tenant_admin 调 GET /tenants 仍能拿自己 row（用于左上角 switcher），
// 但 POST/PUT/DELETE 被 authz.Require("tenant.manage") 拒绝。后端 503/403。
import { useCallback, useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { Plus, Pencil, Trash2, Building } from 'lucide-react'
import { tenantApi, cn, useTranslation } from '@mxid/shared'
import type { Tenant } from '@mxid/shared'
import PageHeader from '../../components/layout/PageHeader'
import { Field, Input, Select, Button, Tag, Modal, EmptyState, LoadingState, pageMotion } from '../../components/ui'
import { toast, extractMessage } from '../../components/ui/toast'

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
      toast.success(t('common.saveSuccess'))
      setShowForm(false)
      await load()
    } catch (e) {
      toast.error(t('common.saveFailed'), extractMessage(e))
    } finally {
      setSaving(false)
    }
  }

  const remove = async (tenant: Tenant) => {
    if (!confirm(t('tenants.confirmDelete', { name: tenant.name }))) return
    try {
      await tenantApi.delete(tenant.id)
      toast.success(t('common.deleteSuccess'))
      await load()
    } catch (e) {
      toast.error(t('common.deleteFailed'), extractMessage(e))
    }
  }

  return (
    <motion.div {...pageMotion}>
      <PageHeader
        title={t('tenants.title')}
        description={t('tenants.subtitle')}
        actions={
          <Button onClick={openCreate} icon={<Plus className="h-4 w-4" />}>
            {t('tenants.create')}
          </Button>
        }
      />

      <div className="rounded-xl border border-gray-100 bg-white shadow-sm">
        {loading ? (
          <LoadingState />
        ) : items.length === 0 ? (
          <EmptyState>{t('tenants.empty')}</EmptyState>
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
                        <Tag variant="green">{t('common.enabled')}</Tag>
                      ) : (
                        <Tag variant="gray">{t('common.disabled')}</Tag>
                      )}
                      {String(tenant.id) === '1' && <Tag variant="amber">{t('tenants.defaultTag')}</Tag>}
                    </div>
                    <p className="mt-0.5 text-xs text-gray-400">id: {tenant.id}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Button size="sm" variant="secondary" onClick={() => openEdit(tenant)} icon={<Pencil className="h-3.5 w-3.5" />}>
                    {t('common.edit')}
                  </Button>
                  {String(tenant.id) !== '1' && (
                    <Button size="sm" variant="danger" onClick={() => remove(tenant)} icon={<Trash2 className="h-3.5 w-3.5" />}>
                      {t('common.delete')}
                    </Button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <Modal
        open={showForm}
        onClose={() => setShowForm(false)}
        title={editing ? t('tenants.editTitle') : t('tenants.createTitle')}
      >
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
            <Select value={form.status} onChange={(e) => setForm({ ...form, status: Number(e.target.value) })}>
              <option value={1}>{t('common.enable')}</option>
              <option value={2}>{t('common.disable')}</option>
            </Select>
          </Field>
          <div className="flex justify-end gap-3 pt-2">
            <Button type="button" variant="secondary" onClick={() => setShowForm(false)}>{t('common.cancel')}</Button>
            <Button type="submit" loading={saving}>
              {editing ? t('common.save') : t('common.create')}
            </Button>
          </div>
        </form>
      </Modal>
    </motion.div>
  )
}
