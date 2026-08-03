// Tenant 管理页 — super_admin only.
//
// 普通 tenant_admin 调 GET /tenants 仍能拿自己 row（用于左上角 switcher），
// 但 PUT/DELETE 被 authz.Require("tenant.manage") 拒绝。产品永久单租户：
// 没有创建入口（后端也无 POST /tenants 路由），默认租户由迁移种子。
import { useCallback, useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { Pencil, Trash2, Building } from 'lucide-react'
import { tenantApi, useTranslation, TenantStatus } from '@mxid/shared'
import type { Tenant } from '@mxid/shared'
import PageHeader from '../../components/layout/PageHeader'
import { Field, Input, Select, Button, Tag, Modal, EmptyState, LoadingState, Card, ConfirmDialog, pageMotion } from '../../components/ui'
import { toast, extractMessage } from '../../components/ui/toast'

export default function TenantsPage() {
  const { t } = useTranslation()
  const [items, setItems] = useState<Tenant[]>([])
  const [loading, setLoading] = useState(true)
  const [editing, setEditing] = useState<Tenant | null>(null)
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ name: '', code: '', status: 1 })
  const [saving, setSaving] = useState(false)
  const [delTarget, setDelTarget] = useState<Tenant | null>(null)
  const [deleting, setDeleting] = useState(false)

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

  const openEdit = (tenant: Tenant) => {
    setEditing(tenant)
    setForm({ name: tenant.name, code: tenant.code, status: tenant.status })
    setShowForm(true)
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!editing) return
    setSaving(true)
    try {
      await tenantApi.update(editing.id, { name: form.name, status: form.status })
      toast.success(t('common.saveSuccess'))
      setShowForm(false)
      await load()
    } catch (e) {
      toast.error(t('common.saveFailed'), extractMessage(e))
    } finally {
      setSaving(false)
    }
  }

  const confirmRemove = async () => {
    if (!delTarget) return
    setDeleting(true)
    try {
      await tenantApi.delete(delTarget.id)
      toast.success(t('common.deleteSuccess'))
      setDelTarget(null)
      await load()
    } catch (e) {
      toast.error(t('common.deleteFailed'), extractMessage(e))
    } finally {
      setDeleting(false)
    }
  }

  return (
    <motion.div {...pageMotion}>
      <PageHeader
        title={t('tenants.title')}
        description={t('tenants.subtitle')}
      />

      <Card className="overflow-hidden hover:shadow-card">
        {loading ? (
          <LoadingState />
        ) : items.length === 0 ? (
          <EmptyState>{t('tenants.empty')}</EmptyState>
        ) : (
          <div className="divide-y divide-border">
            {items.map((tenant) => (
              <div key={tenant.id} className="flex items-center justify-between p-5 transition-colors hover:bg-surface-muted">
                <div className="flex items-center gap-4">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
                    <Building className="h-5 w-5" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-ink">{tenant.name}</span>
                      <code className="rounded bg-surface-muted px-1.5 py-0.5 text-xs text-muted">{tenant.code}</code>
                      {tenant.status === TenantStatus.Enabled ? (
                        <Tag variant="green">{t('common.enabled')}</Tag>
                      ) : (
                        <Tag variant="gray">{t('common.disabled')}</Tag>
                      )}
                      {String(tenant.id) === '1' && <Tag variant="amber">{t('tenants.defaultTag')}</Tag>}
                    </div>
                    <p className="mt-0.5 text-xs text-faint">id: {tenant.id}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Button size="sm" variant="secondary" onClick={() => openEdit(tenant)} icon={<Pencil className="h-3.5 w-3.5" />}>
                    {t('common.edit')}
                  </Button>
                  {String(tenant.id) !== '1' && (
                    <Button size="sm" variant="danger" onClick={() => setDelTarget(tenant)} icon={<Trash2 className="h-3.5 w-3.5" />}>
                      {t('common.delete')}
                    </Button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Modal
        open={showForm}
        onClose={() => setShowForm(false)}
        title={t('tenants.editTitle')}
      >
        <form onSubmit={submit} className="space-y-4">
          <Field label={t('tenants.fields.name')} required>
            <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
          </Field>
          <Field label={t('tenants.fields.codeImmutable')} hint={t('tenants.fields.codeHint')}>
            <Input value={form.code} disabled />
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
              {t('common.save')}
            </Button>
          </div>
        </form>
      </Modal>

      <ConfirmDialog
        open={!!delTarget}
        title={t('tenants.confirmDelete', { name: delTarget?.name ?? '' })}
        desc={t('common.cantUndo')}
        loading={deleting}
        onConfirm={confirmRemove}
        onCancel={() => setDelTarget(null)}
      />
    </motion.div>
  )
}
