// AppGroupsTab — manage app groups (UI categorisation containers).
//
// Lives under /apps page as a tab so admins don't context-switch out of the
// app management area. Each group has a name + code + sort_order, and a
// drag-free list of member apps (add/remove via the drawer on the right).
import { useCallback, useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Plus, Pencil, Trash2, Loader2, X, LayoutGrid, Search } from 'lucide-react'
import { appApi, appGroupApi, cn, useTranslation } from '@mxid/shared'
import type { App, AppGroup } from '@mxid/shared'
import { Field, CodeField, Button, ConfirmDialog } from '../../components/ui'
import AccessPolicyTab from './AccessPolicyTab'
import AppRolesTab from './AppRolesTab'
import AppGroupRolesAggregated from './AppGroupRolesAggregated'
import { toast, extractMessage } from '../../components/ui/toast'

export default function AppGroupsTab() {
  const { t } = useTranslation()
  const [groups, setGroups] = useState<AppGroup[]>([])
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<AppGroup | null>(null)
  const [delGroup, setDelGroup] = useState<AppGroup | null>(null)
  const [deleting, setDeleting] = useState(false)

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

  const confirmRemove = async () => {
    const g = delGroup
    if (!g) return
    setDeleting(true)
    try {
      await appGroupApi.delete(g.id)
      if (selected?.id === g.id) setSelected(null)
      setDelGroup(null)
      await load()
      toast.success(t("common.success"))
    } catch (e) {
      toast.error(t("common.failed"), extractMessage(e))
    } finally {
      setDeleting(false)
    }
  }

  return (
    <div className="flex gap-4">
      {/* Left: list */}
      <div className="w-72 shrink-0 rounded-xl border border-border bg-surface p-4 shadow-sm">
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-ink">{t('apps.appGroups.title')}</h3>
          <Button size="sm" onClick={openCreate} icon={<Plus className="h-3.5 w-3.5" />}>
            {t('apps.appGroups.create')}
          </Button>
        </div>
        {loading ? (
          <p className="py-6 text-center text-sm text-faint">
            <Loader2 className="mx-auto h-4 w-4 animate-spin" />
          </p>
        ) : groups.length === 0 ? (
          <p className="py-6 text-center text-sm text-faint">{t('apps.appGroups.empty')}</p>
        ) : (
          <div className="space-y-1">
            {groups.map((g) => (
              <button
                key={g.id}
                onClick={() => setSelected(g)}
                className={cn(
                  'flex w-full items-center justify-between rounded-lg px-2.5 py-2 text-left text-sm',
                  selected?.id === g.id ? 'bg-primary/10 text-primary' : 'hover:bg-surface-muted',
                )}
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <LayoutGrid className="h-3.5 w-3.5 shrink-0" />
                    <span className="truncate font-medium">{g.name}</span>
                  </div>
                  <p className="ml-5 truncate text-xs text-faint">{g.code}</p>
                </div>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Right: detail + members */}
      <div className="flex-1 rounded-xl border border-border bg-surface shadow-sm">
        {selected ? (
          <GroupDetail
            group={selected}
            onEdit={() => openEdit(selected)}
            onDelete={() => setDelGroup(selected)}
            onMutated={load}
          />
        ) : (
          <div className="py-16 text-center text-sm text-faint">{t('apps.appGroupDetail.selectGroupHint')}</div>
        )}
      </div>

      <AnimatePresence>
        {showForm && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-md rounded-xl bg-surface p-6 shadow-xl"
            >
              <div className="mb-4 flex items-center justify-between">
                <h3 className="text-lg font-semibold">{editing ? t('apps.appGroupDetail.editGroup') : t('apps.appGroupDetail.createGroup')}</h3>
                <button onClick={() => setShowForm(false)} className="rounded p-1 text-faint hover:bg-surface-muted">
                  <X className="h-4 w-4" />
                </button>
              </div>
              <form onSubmit={submit} className="space-y-4">
                <Field label={`${t('apps.appGroups.name')} *`} hint={t('apps.appGroups.nameHint')}>
                  <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required className="w-full rounded-lg border border-border px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20" />
                </Field>
                <Field
                  label={editing ? t('apps.appGroupDetail.codeUneditable') : t('apps.appGroupDetail.codeRequired')}
                  hint={t('apps.appGroupDetail.codeHint')}
                >
                  {editing ? (
                    <input
                      value={form.code}
                      disabled
                      className="w-full rounded-lg border border-border bg-surface-muted px-3 py-2 text-sm text-muted outline-none"
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
                  <textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} rows={3} className="w-full rounded-lg border border-border px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20" />
                </Field>
                <Field label={t('apps.appGroups.sortOrder')} hint={t('apps.appGroups.sortOrderHint')}>
                  <input type="number" value={form.sort_order} onChange={(e) => setForm({ ...form, sort_order: Number(e.target.value) })} className="w-full rounded-lg border border-border px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20" />
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

      <ConfirmDialog
        open={!!delGroup}
        title={t('apps.appGroups.delete', { name: delGroup?.name ?? '' })}
        desc={t('common.cantUndo')}
        loading={deleting}
        onConfirm={confirmRemove}
        onCancel={() => setDelGroup(null)}
      />
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
  // Member apps come straight from the relation endpoint (the authoritative
  // membership, never truncated). The "available to add" picker searches the
  // catalog server-side so groups on tenants with >100 apps aren't clipped.
  const [members, setMembers] = useState<App[]>([])
  const [memberIDs, setMemberIDs] = useState<Set<string>>(new Set())
  const [loading, setLoading] = useState(true)
  const [picking, setPicking] = useState(false)
  const [busy, setBusy] = useState<string | null>(null)
  // Picker search state.
  const [search, setSearch] = useState('')
  const [candidates, setCandidates] = useState<App[]>([])
  const [candLoading, setCandLoading] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const joined = await appGroupApi.listApps(group.id)
      setMembers(joined ?? [])
      setMemberIDs(new Set((joined ?? []).map((a) => a.id)))
    } finally {
      setLoading(false)
    }
  }, [group.id])

  useEffect(() => {
    load()
  }, [load])

  // Debounced server-side candidate search — only while the picker is open.
  // Excludes current members client-side (the list API has no "not-in-group"
  // filter, and members are few enough to filter here).
  useEffect(() => {
    if (!picking) return
    let cancelled = false
    const handle = setTimeout(async () => {
      setCandLoading(true)
      try {
        const r = await appApi.list({ search, page: 1, page_size: 50 })
        if (!cancelled) setCandidates((r.items ?? []).filter((a) => !memberIDs.has(a.id)))
      } catch {
        if (!cancelled) setCandidates([])
      } finally {
        if (!cancelled) setCandLoading(false)
      }
    }, 250)
    return () => {
      cancelled = true
      clearTimeout(handle)
    }
  }, [picking, search, memberIDs])

  const openPicker = () => {
    setSearch('')
    setCandidates([])
    setPicking(true)
  }

  const addApp = async (app: App) => {
    setBusy(app.id)
    try {
      await appGroupApi.addApp(group.id, app.id)
      setMembers((prev) => (prev.some((m) => m.id === app.id) ? prev : [app, ...prev]))
      setMemberIDs((prev) => new Set(prev).add(app.id))
      setCandidates((prev) => prev.filter((c) => c.id !== app.id))
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
      setMembers((prev) => prev.filter((m) => m.id !== app.id))
      setMemberIDs((prev) => {
        const next = new Set(prev)
        next.delete(app.id)
        return next
      })
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
      <div className="flex items-start justify-between border-b border-border px-6 py-4">
        <div>
          <h2 className="text-lg font-semibold text-ink">{group.name}</h2>
          <p className="text-xs text-muted">
            <code className="rounded bg-surface-muted px-1.5 py-0.5">{group.code}</code>
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
      <div className="flex gap-6 border-b border-border px-6">
        {(['members', 'access', 'roles'] as const).map((tabKey) => (
          <button
            key={tabKey}
            onClick={() => setTab(tabKey)}
            className={cn(
              'border-b-2 px-1 py-2.5 text-sm font-medium transition-colors',
              tab === tabKey ? 'border-primary text-primary' : 'border-transparent text-muted hover:text-ink',
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
            <h3 className="mb-2 text-base font-semibold text-ink">{t('apps.appGroupDetail.rolesSummaryTitle')}</h3>
            <p className="mb-3 text-sm text-muted">
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
          <h3 className="text-sm font-semibold text-ink">{t('apps.appGroupDetail.joinedApps')}</h3>
          <button onClick={openPicker} className="inline-flex items-center gap-1 rounded-lg bg-primary px-2.5 py-1 text-xs font-medium text-white hover:bg-primary-hover">
            <Plus className="h-3.5 w-3.5" /> {t('apps.appGroupDetail.addApp')}
          </button>
        </div>
        {loading ? (
          <p className="py-6 text-center text-sm text-faint">
            <Loader2 className="mx-auto h-4 w-4 animate-spin" />
          </p>
        ) : members.length === 0 ? (
          <p className="py-6 text-center text-sm text-faint">{t('apps.appGroupDetail.emptyMembers')}</p>
        ) : (
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {members.map((a) => (
              <AppCard key={a.id} app={a} action={
                <button
                  onClick={() => removeApp(a)}
                  disabled={busy === a.id}
                  className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-faint hover:bg-red-50 hover:text-red-500 disabled:opacity-50"
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
              className="w-full max-w-2xl max-h-[80vh] overflow-y-auto rounded-xl bg-surface p-6 shadow-xl"
            >
              <div className="mb-4 flex items-center justify-between">
                <h3 className="text-lg font-semibold">{t('apps.appGroupDetail.addAppTitle', { name: group.name })}</h3>
                <button onClick={() => setPicking(false)} className="rounded p-1 text-faint hover:bg-surface-muted">
                  <X className="h-4 w-4" />
                </button>
              </div>
              <div className="mb-3 flex items-center rounded-lg border border-border px-3 focus-within:border-primary focus-within:ring-2 focus-within:ring-primary/20">
                <Search className="h-4 w-4 shrink-0 text-faint" />
                <input
                  type="text"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder={t('apps.appGroupDetail.searchAppsPlaceholder')}
                  className="w-full bg-transparent px-2 py-2 text-sm outline-none"
                  autoFocus
                />
                {candLoading && <Loader2 className="h-4 w-4 shrink-0 animate-spin text-faint" />}
              </div>
              {candLoading && candidates.length === 0 ? (
                <p className="py-8 text-center text-sm text-faint"><Loader2 className="mx-auto h-4 w-4 animate-spin" /></p>
              ) : candidates.length === 0 ? (
                <p className="py-8 text-center text-sm text-faint">{t('apps.appGroupDetail.noCandidates')}</p>
              ) : (
                <div className="space-y-2">
                  {candidates.map((a) => (
                    <div key={a.id} className="flex items-center justify-between rounded-lg border border-border px-3 py-2 hover:bg-surface-muted">
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium text-ink">{a.name}</span>
                          <code className="rounded bg-surface-muted px-1.5 py-0.5 text-xs text-muted">{a.code}</code>
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
    <div className="flex items-center justify-between rounded-lg border border-border p-3 hover:bg-surface-muted">
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          <span className="truncate text-sm font-medium text-ink">{app.name}</span>
          <span className="rounded-full bg-blue-50 px-1.5 py-0.5 text-[10px] text-blue-700">{app.protocol}</span>
        </div>
        <code className="truncate text-xs text-faint">{app.code}</code>
      </div>
      {action}
    </div>
  )
}
