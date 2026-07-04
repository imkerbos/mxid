// AppRolesReverseTab — for a user group, shows which app roles this
// group is currently bound to (across every app + app-group). Lets the
// admin add/remove bindings without leaving the user group page.
//
// Backend: GET /groups/:id/app-role-bindings returns enriched view
// rows (role_name + target_name).
import { useCallback, useEffect, useState } from 'react'
import { Plus, Trash2, Loader2, Shield, AppWindow, LayoutGrid } from 'lucide-react'
import { appRoleApi, appApi, appGroupApi, useTranslation } from '@mxid/shared'
import type {
  ReverseAppRoleBinding, AppRole, App as AppT, AppGroup,
} from '@mxid/shared'
import { Field, Select, Button, Tag, ConfirmDialog } from '../../components/ui'
import { toast } from '../../components/ui/toast'

export default function AppRolesReverseTab({ groupId }: { groupId: string }) {
  const { t } = useTranslation()
  const [list, setList] = useState<ReverseAppRoleBinding[]>([])
  const [loading, setLoading] = useState(true)
  const [showAdd, setShowAdd] = useState(false)
  const [delBinding, setDelBinding] = useState<ReverseAppRoleBinding | null>(null)
  const [deleting, setDeleting] = useState(false)

  const reload = useCallback(async () => {
    setLoading(true)
    try {
      const rows = await appRoleApi.listBindingsForUserGroup(groupId)
      setList(rows)
    } catch {
      toast.error(t('groupAppRoles.loadFailed'))
    } finally {
      setLoading(false)
    }
  }, [groupId, t])

  useEffect(() => { reload() }, [reload])

  const confirmDelete = async () => {
    const b = delBinding
    if (!b) return
    setDeleting(true)
    try {
      await appRoleApi.deleteBinding(b.target_type, b.target_id, b.id)
      setDelBinding(null)
      toast.success(t("common.success"))
      reload()
    } catch (e) {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message
      toast.error(t("common.failed"), msg)
    } finally {
      setDeleting(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="text-base font-semibold text-ink">{t('groupAppRoles.title')}</h3>
          <p className="mt-0.5 text-sm text-muted">
            {t('groupAppRoles.description')}
            <code className="rounded bg-surface-muted px-1">app_roles</code>{t('groupAppRoles.descriptionTail')}
          </p>
        </div>
        <Button variant="primary" size="sm" onClick={() => setShowAdd(true)}>
          <Plus className="h-4 w-4" /> {t('groupAppRoles.addBinding')}
        </Button>
      </div>

      {loading ? (
        <Loader2 className="mx-auto my-12 h-6 w-6 animate-spin text-faint" />
      ) : list.length === 0 ? (
        <div className="rounded-lg border border-dashed border-border py-8 text-center text-sm text-faint">
          {t('groupAppRoles.empty')}
        </div>
      ) : (
        <div className="space-y-2">
          {list.map((b) => (
            <BindingRow key={b.id} binding={b} onDelete={setDelBinding} />
          ))}
        </div>
      )}

      {showAdd && (
        <AddModal
          groupId={groupId}
          onClose={() => setShowAdd(false)}
          onSaved={() => { setShowAdd(false); reload() }}
        />
      )}

      <ConfirmDialog
        open={!!delBinding}
        title={t('groupAppRoles.confirmRemove', { target: delBinding?.target_name ?? '', role: delBinding?.role_name ?? '' })}
        loading={deleting}
        onConfirm={confirmDelete}
        onCancel={() => setDelBinding(null)}
      />
    </div>
  )
}

function BindingRow({ binding, onDelete }: { binding: ReverseAppRoleBinding; onDelete: (b: ReverseAppRoleBinding) => void }) {
  const { t } = useTranslation()
  const Icon = binding.target_type === 'app' ? AppWindow : LayoutGrid
  return (
    <div className="flex items-center gap-4 rounded-lg border border-border bg-surface px-4 py-3 hover:border-primary/30">
      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-surface-muted">
        <Icon className="h-4 w-4 text-muted" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="truncate text-sm font-medium text-ink">{binding.target_name}</div>
        <div className="flex items-center gap-1.5 truncate text-xs text-faint">
          <span>{binding.target_type === 'app' ? t('groupAppRoles.targetTypeApp') : t('groupAppRoles.targetTypeAppGroup')}</span>
          <span>·</span>
          <span className="font-mono">{binding.target_code}</span>
        </div>
      </div>
      <span className="shrink-0 text-faint">→</span>
      <div className="flex shrink-0 items-center gap-2 rounded-lg bg-primary/5 px-3 py-1.5">
        <Shield className="h-3.5 w-3.5 text-primary" />
        <span className="text-sm font-medium text-primary">{binding.role_name}</span>
        <span className="font-mono text-xs text-primary/60">{binding.role_code}</span>
      </div>
      <button onClick={() => onDelete(binding)} className="shrink-0 rounded-md p-1.5 text-faint hover:bg-red-50 hover:text-red-500">
        <Trash2 className="h-4 w-4" />
      </button>
    </div>
  )
}

function AddModal({
  groupId,
  onClose,
  onSaved,
}: {
  groupId: string
  onClose: () => void
  onSaved: () => void
}) {
  const { t } = useTranslation()
  const [targetType, setTargetType] = useState<'app' | 'app-group'>('app')
  const [targetId, setTargetId] = useState<string>('')
  const [apps, setApps] = useState<AppT[]>([])
  const [appGroups, setAppGroups] = useState<AppGroup[]>([])
  const [roles, setRoles] = useState<AppRole[]>([])
  const [appRoleId, setAppRoleId] = useState<string>('')
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)

  // Load app or app-group list when type switches.
  useEffect(() => {
    setTargetId('')
    setRoles([])
    const load = async () => {
      try {
        if (targetType === 'app') {
          const r = await appApi.list({ page: 1, page_size: 200 })
          setApps(r.items)
        } else {
          const r = await appGroupApi.list()
          setAppGroups(r)
        }
      } catch {
        toast.error(t('groupAppRoles.loadListFailed'))
      }
    }
    load()
  }, [targetType, t])

  // Load roles for the chosen target.
  useEffect(() => {
    setAppRoleId('')
    if (!targetId) { setRoles([]); return }
    setLoading(true)
    appRoleApi.listRoles(targetType, targetId)
      .then(setRoles)
      .catch(() => toast.error(t('groupAppRoles.loadRolesFailed')))
      .finally(() => setLoading(false))
  }, [targetType, targetId, t])

  const handleSave = async () => {
    if (!targetId || !appRoleId) { toast.warning(t('groupAppRoles.pickTargetAndRole')); return }
    setSaving(true)
    try {
      await appRoleApi.createBinding(targetType, targetId, {
        app_role_id: appRoleId,
        subject_type: 'group',
        subject_id: groupId,
      })
      toast.success(t('groupAppRoles.bound'))
      onSaved()
    } catch (e) {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message
      toast.error(t('groupAppRoles.bindFailed'), msg)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/40 p-4">
      <div className="w-full max-w-md rounded-xl bg-surface p-6 shadow-xl">
        <h3 className="mb-4 text-lg font-semibold">{t('groupAppRoles.addModalTitle')}</h3>
        <div className="space-y-4">
          <Field label={t('groupAppRoles.fields.targetType')}>
            <Select value={targetType} onChange={(e) => setTargetType(e.target.value as 'app' | 'app-group')}>
              <option value="app">{t('groupAppRoles.fields.targetTypeApp')}</option>
              <option value="app-group">{t('groupAppRoles.fields.targetTypeAppGroup')}</option>
            </Select>
          </Field>
          <Field label={targetType === 'app' ? t('groupAppRoles.fields.pickApp') : t('groupAppRoles.fields.pickAppGroup')}>
            <Select value={targetId} onChange={(e) => setTargetId(e.target.value)}>
              <option value="">{t('groupAppRoles.fields.pleaseSelect')}</option>
              {targetType === 'app' && apps.map((a) => (
                <option key={String(a.id)} value={String(a.id)}>{a.name} ({a.code})</option>
              ))}
              {targetType === 'app-group' && appGroups.map((g) => (
                <option key={String(g.id)} value={String(g.id)}>{g.name} ({g.code})</option>
              ))}
            </Select>
          </Field>
          {targetId && (
            <Field label={t('groupAppRoles.fields.targetRole')}>
              {loading ? (
                <div className="flex h-10 items-center"><Loader2 className="h-4 w-4 animate-spin text-faint" /></div>
              ) : roles.length === 0 ? (
                <p className="text-xs text-amber-600">{t('groupAppRoles.fields.noRolesHint')}</p>
              ) : (
                <Select value={appRoleId} onChange={(e) => setAppRoleId(e.target.value)}>
                  <option value="">{t('groupAppRoles.fields.pleaseSelect')}</option>
                  {roles.map((r) => <option key={r.id} value={r.id}>{r.name} ({r.code})</option>)}
                </Select>
              )}
            </Field>
          )}
        </div>
        <div className="mt-6 flex justify-end gap-2">
          <Button variant="secondary" onClick={onClose}>{t('common.cancel')}</Button>
          <Button variant="primary" onClick={handleSave} disabled={saving || !appRoleId}>
            {saving && <Loader2 className="h-4 w-4 animate-spin" />}
            <Tag variant="primary">{t('groupAppRoles.bindBtn')}</Tag>
          </Button>
        </div>
      </div>
    </div>
  )
}
