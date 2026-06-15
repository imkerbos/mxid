// AppGroupsTab — manage app groups (UI categorisation containers).
//
// Lives under /apps page as a tab so admins don't context-switch out of the
// app management area. Each group has a name + code + sort_order, and a
// drag-free list of member apps (add/remove via the drawer on the right).
import { useCallback, useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Plus, Pencil, Trash2, Loader2, X, LayoutGrid } from 'lucide-react'
import { appApi, appGroupApi, cn, useTranslation } from '@mxid/shared'
import type { App, AppGroup } from '@mxid/shared'
import { Field, CodeField, Button } from '../../components/ui'
import AccessPolicyTab from './AccessPolicyTab'
import AppRolesTab from './AppRolesTab'
import AppGroupRolesAggregated from './AppGroupRolesAggregated'
import { toast, extractMessage } from '../../components/ui/toast'

export default function AppGroupsTab() {
  const { t } = useTranslation()
  const [groups, setGroups] = useState<AppGroup[]>([])
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<AppGroup | null>(null)

  // create/edit modal
  const [editing, setEditing] = useState<AppGroup | null>(null)
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ name: '', code: '', description: '', sort_order: 0 })
  const [saving, setSaving] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await appGroupApi.list()
      setGroups(res ?? [])
      // Keep selection in sync after edits.
      if (selected) {
        const fresh = (res ?? []).find((g) => g.id === selected.id)
        setSelected(fresh ?? null)
      }
    } finally {
      setLoading(false)
    }
  }, [selected])

  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const openCreate = () => {
    setEditing(null)
    setForm({ name: '', code: '', description: '', sort_order: 0 })
    setShowForm(true)
  }
  const openEdit = (g: AppGroup) => {
    setEditing(g)
    setForm({
      name: g.name,
      code: g.code,
      description: g.description ?? '',
      sort_order: g.sort_order,
    })
    setShowForm(true)
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!form.name || (!editing && !form.code)) return
    setSaving(true)
    try {
      if (editing) {
        await appGroupApi.update(editing.id, {
          name: form.name,
          description: form.description || undefined,
          sort_order: form.sort_order,
        })
      } else {
        await appGroupApi.create({
          name: form.name,
          code: form.code,
          description: form.description || undefined,
          sort_order: form.sort_order,
        })
      }
      setShowForm(false)
      await load()
      toast.success(editing ? t('apps.appGroupDetail.saved') : t('apps.appGroupDetail.created'))
    } catch (e) {
      toast.error(editing ? t('apps.appGroupDetail.saveFailed') : t('apps.appGroupDetail.createFailed'), extractMessage(e))
    } finally {
      setSaving(false)
    }
  }

  const remove = async (g: AppGroup) => {
    if (!confirm(t('apps.appGroups.delete', { name: g.name }))) return
    try {
      await appGroupApi.delete(g.id)
      if (selected?.id === g.id) setSelected(null)
      await load()
      toast.success(t("common.success"))
    } catch (e) {
      toast.error(t("common.failed"), extractMessage(e))
    }
  }

  return (
    <div className="flex gap-4">
      {/* Left: list */}
      <div className="w-72 shrink-0 rounded-xl border border-gray-100 bg-white p-4 shadow-sm">
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-gray-700">{t('apps.appGroups.title')}</h3>
          <Button size="sm" onClick={openCreate} icon={<Plus className="h-3.5 w-3.5" />}>
            {t('apps.appGroups.create')}
          </Button>
        </div>
        {loading ? (
          <p className="py-6 text-center text-sm text-gray-400">
            <Loader2 className="mx-auto h-4 w-4 animate-spin" />
          </p>
        ) : groups.length === 0 ? (
          <p className="py-6 text-center text-sm text-gray-400">{t('apps.appGroups.empty')}</p>
        ) : (
          <div className="space-y-1">
            {groups.map((g) => (
              <button
                key={g.id}
                onClick={() => setSelected(g)}
                className={cn(
                  'flex w-full items-center justify-between rounded-lg px-2.5 py-2 text-left text-sm',
                  selected?.id === g.id ? 'bg-primary/10 text-primary' : 'hover:bg-gray-50',
                )}
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <LayoutGrid className="h-3.5 w-3.5 shrink-0" />
                    <span className="truncate font-medium">{g.name}</span>
                  </div>
                  <p className="ml-5 truncate text-xs text-gray-400">{g.code}</p>
                </div>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Right: detail + members */}
      <div className="flex-1 rounded-xl border border-gray-100 bg-white shadow-sm">
        {selected ? (
          <GroupDetail
            group={selected}
            onEdit={() => openEdit(selected)}
            onDelete={() => remove(selected)}
            onMutated={load}
          />
        ) : (
          <div className="py-16 text-center text-sm text-gray-400">{t('apps.appGroupDetail.selectGroupHint')}</div>
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
                <h3 className="text-lg font-semibold">{editing ? t('apps.appGroupDetail.editGroup') : t('apps.appGroupDetail.createGroup')}</h3>
                <button onClick={() => setShowForm(false)} className="rounded p-1 text-gray-400 hover:bg-gray-100">
                  <X className="h-4 w-4" />
                </button>
              </div>
              <form onSubmit={submit} className="space-y-4">
                <Field label={`${t('apps.appGroups.name')} *`} hint={t('apps.appGroups.nameHint')}>
                  <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20" />
                </Field>
                <Field
                  label={editing ? t('apps.appGroupDetail.codeUneditable') : t('apps.appGroupDetail.codeRequired')}
                  hint={t('apps.appGroupDetail.codeHint')}
                >
                  {editing ? (
                    <input
                      value={form.code}
                      disabled
                      className="w-full rounded-lg border border-gray-200 bg-gray-50 px-3 py-2 text-sm text-gray-500 outline-none"
                    />
                  ) : (
                    <CodeField
                      value={form.code}
                      onChange={(v) => setForm({ ...form, code: v })}
                      nameForSlug={form.name}
                      prefix="grp"
                      placeholder="office-suite / devops ..."
                    />
                  )}
                </Field>
                <Field label={t('apps.appGroups.desc')}>
                  <textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} rows={3} className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20" />
                </Field>
                <Field label={t('apps.appGroups.sortOrder')} hint={t('apps.appGroups.sortOrderHint')}>
                  <input type="number" value={form.sort_order} onChange={(e) => setForm({ ...form, sort_order: Number(e.target.value) })} className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20" />
                </Field>
                <div className="flex justify-end gap-3 pt-2">
                  <Button type="button" variant="secondary" onClick={() => setShowForm(false)}>{t('common.cancel')}</Button>
                  <Button type="submit" loading={saving}>
                    {editing ? t('common.save') : t('common.create')}
                  </Button>
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  )
}

/* ──────────────────────── group detail ──────────────────────── */

function GroupDetail({
  group,
  onEdit,
  onDelete,
  onMutated,
}: {
  group: AppGroup
  onEdit: () => void
  onDelete: () => void
  onMutated: () => Promise<void> | void
}) {
  const { t } = useTranslation()
  const [tab, setTab] = useState<'members' | 'access' | 'roles'>('members')
  // Local copy of all apps to drive both the member list AND the
  // "available to add" picker. The relation table doesn't return the full
  // app rows, so we fetch /apps once and filter in-memory — fine for
  // the typical tenant scale (dozens, not thousands).
  const [allApps, setAllApps] = useState<App[]>([])
  const [memberIDs, setMemberIDs] = useState<Set<string>>(new Set())
  const [loading, setLoading] = useState(true)
  const [picking, setPicking] = useState(false)
  const [busy, setBusy] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      // Two fetches in parallel:
      //   - /apps         → full catalog (drives "available to add" picker)
      //   - /app-groups/:id/apps → current membership (persists across reloads)
      const [apps, joined] = await Promise.all([
        appApi.list({ page: 1, page_size: 200 }),
        appGroupApi.listApps(group.id),
      ])
      setAllApps(apps.items ?? [])
      setMemberIDs(new Set((joined ?? []).map((a) => a.id)))
    } finally {
      setLoading(false)
    }
  }, [group.id])

  useEffect(() => {
    load()
  }, [load])

  const members = allApps.filter((a) => memberIDs.has(a.id))
  const candidates = allApps.filter((a) => !memberIDs.has(a.id))

  const addApp = async (app: App) => {
    setBusy(app.id)
    try {
      await appGroupApi.addApp(group.id, app.id)
      const next = new Set(memberIDs)
      next.add(app.id)
      setMemberIDs(next)
      await onMutated?.()
      toast.success(t('apps.appGroupDetail.added', { name: app.name }))
    } catch (e) {
      toast.error(t('apps.appGroupDetail.addFailed'), extractMessage(e))
    } finally {
      setBusy(null)
    }
  }
  const removeApp = async (app: App) => {
    setBusy(app.id)
    try {
      await appGroupApi.removeApp(group.id, app.id)
      const next = new Set(memberIDs)
      next.delete(app.id)
      setMemberIDs(next)
      await onMutated?.()
      toast.success(t('apps.appGroupDetail.removed', { name: app.name }))
    } catch (e) {
      toast.error(t("common.failed"), extractMessage(e))
    } finally {
      setBusy(null)
    }
  }

  return (
    <div>
      {/* header */}
      <div className="flex items-start justify-between border-b border-gray-100 px-6 py-4">
        <div>
          <h2 className="text-lg font-semibold text-gray-900">{group.name}</h2>
          <p className="text-xs text-gray-500">
            <code className="rounded bg-gray-100 px-1.5 py-0.5">{group.code}</code>
            {' · '}{t('apps.appGroupDetail.sortLabel', { order: group.sort_order })}
            {group.description ? ` · ${group.description}` : ''}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="secondary" onClick={onEdit} icon={<Pencil className="h-3.5 w-3.5" />}>
            {t('common.edit')}
          </Button>
          <Button size="sm" variant="danger" onClick={onDelete} icon={<Trash2 className="h-3.5 w-3.5" />}>
            {t('common.delete')}
          </Button>
        </div>
      </div>

      {/* tabs */}
      <div className="flex gap-6 border-b border-gray-100 px-6">
        {(['members', 'access', 'roles'] as const).map((tabKey) => (
          <button
            key={tabKey}
            onClick={() => setTab(tabKey)}
            className={cn(
              'border-b-2 px-1 py-2.5 text-sm font-medium transition-colors',
              tab === tabKey ? 'border-primary text-primary' : 'border-transparent text-gray-500 hover:text-gray-700',
            )}
          >
            {tabKey === 'members'
              ? t('apps.appGroupDetail.memberAppsTab')
              : tabKey === 'access'
                ? t('apps.appGroupDetail.accessTab')
                : t('apps.appGroupDetail.rolesTab')}
          </button>
        ))}
      </div>

      {tab === 'access' && (
        <div className="px-6 py-4">
          <AccessPolicyTab owner="app-group" ownerId={String(group.id)} />
        </div>
      )}

      {tab === 'roles' && (
        <div className="space-y-8 px-6 py-4">
          <AppRolesTab owner="app-group" ownerId={String(group.id)} />

          <div>
            <h3 className="mb-2 text-base font-semibold text-gray-900">{t('apps.appGroupDetail.rolesSummaryTitle')}</h3>
            <p className="mb-3 text-sm text-gray-500">
              {t('apps.appGroupDetail.rolesSummaryDesc')}
            </p>
            <AppGroupRolesAggregated groupId={String(group.id)} />
          </div>
        </div>
      )}

      {/* members */}
      {tab === 'members' && (
      <div className="px-6 py-4">
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-gray-700">{t('apps.appGroupDetail.joinedApps')}</h3>
          <button onClick={() => setPicking(true)} className="inline-flex items-center gap-1 rounded-lg bg-primary px-2.5 py-1 text-xs font-medium text-white hover:bg-primary-hover">
            <Plus className="h-3.5 w-3.5" /> {t('apps.appGroupDetail.addApp')}
          </button>
        </div>
        {loading ? (
          <p className="py-6 text-center text-sm text-gray-400">
            <Loader2 className="mx-auto h-4 w-4 animate-spin" />
          </p>
        ) : members.length === 0 ? (
          <p className="py-6 text-center text-sm text-gray-400">{t('apps.appGroupDetail.emptyMembers')}</p>
        ) : (
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {members.map((a) => (
              <AppCard key={a.id} app={a} action={
                <button
                  onClick={() => removeApp(a)}
                  disabled={busy === a.id}
                  className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-gray-400 hover:bg-red-50 hover:text-red-500 disabled:opacity-50"
                >
                  {busy === a.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <X className="h-3 w-3" />}
                  {t('common.remove')}
                </button>
              } />
            ))}
          </div>
        )}
      </div>
      )}

      <AnimatePresence>
        {picking && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-2xl max-h-[80vh] overflow-y-auto rounded-xl bg-white p-6 shadow-xl"
            >
              <div className="mb-4 flex items-center justify-between">
                <h3 className="text-lg font-semibold">{t('apps.appGroupDetail.addAppTitle', { name: group.name })}</h3>
                <button onClick={() => setPicking(false)} className="rounded p-1 text-gray-400 hover:bg-gray-100">
                  <X className="h-4 w-4" />
                </button>
              </div>
              {candidates.length === 0 ? (
                <p className="py-8 text-center text-sm text-gray-400">{t('apps.appGroupDetail.noCandidates')}</p>
              ) : (
                <div className="space-y-2">
                  {candidates.map((a) => (
                    <div key={a.id} className="flex items-center justify-between rounded-lg border border-gray-100 px-3 py-2 hover:bg-gray-50">
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium text-gray-900">{a.name}</span>
                          <code className="rounded bg-gray-100 px-1.5 py-0.5 text-xs text-gray-500">{a.code}</code>
                          <span className="rounded-full bg-blue-50 px-2 py-0.5 text-xs text-blue-700">{a.protocol}</span>
                        </div>
                      </div>
                      <button
                        onClick={() => addApp(a)}
                        disabled={busy === a.id}
                        className="inline-flex items-center gap-1 rounded-md bg-primary/10 px-2.5 py-1 text-xs font-medium text-primary hover:bg-primary/20 disabled:opacity-50"
                      >
                        {busy === a.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <Plus className="h-3 w-3" />}
                        {t('common.add')}
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  )
}

function AppCard({ app, action }: { app: App; action: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between rounded-lg border border-gray-100 p-3 hover:bg-gray-50">
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          <span className="truncate text-sm font-medium text-gray-900">{app.name}</span>
          <span className="rounded-full bg-blue-50 px-1.5 py-0.5 text-[10px] text-blue-700">{app.protocol}</span>
        </div>
        <code className="truncate text-xs text-gray-400">{app.code}</code>
      </div>
      {action}
    </div>
  )
}
