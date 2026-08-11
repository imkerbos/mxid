import { useEffect, useState, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Plus, RotateCcw, Trash2, Loader2, Pencil, ShieldCheck, ShieldOff, Undo2 } from 'lucide-react'
import { userApi, formatDate, statusLabel, statusColor, cn, useTranslation, useUrlState, UserStatus } from '@mxid/shared'
import { Field, pageMotion, Button, Card, DataTable, Modal, Pagination, SearchInput, Select, FilterBar, ConfirmDialog } from '@mxid/shared/ui'
import type { Column } from '@mxid/shared/ui'
import type { User, PaginatedData, UpdateUserRequest } from '@mxid/shared'
import PageHeader from '../../components/layout/PageHeader'
import { toast, extractMessage } from '../../components/ui/toast'

export default function UsersPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [data, setData] = useState<PaginatedData<User>>({ items: [], total: 0, page: 1, page_size: 20 })
  const [loading, setLoading] = useState(true)
  // Filters live in the URL so the view is shareable and survives reload /
  // back-forward (and the post-login bounce back here). showDeleted is a
  // '0' | '1' string (useUrlState only knows string | number) — off by
  // default so the ordinary list stays clean of soft-deleted accounts.
  const [q, setQ] = useUrlState({ page: 1, search: '', status: '', showDeleted: '0' })
  // Local echo for the debounced search box.
  const [search, setSearch] = useState(q.search)
  const timerRef = useRef<ReturnType<typeof setTimeout>>(undefined)

  // Create modal states
  const [showCreate, setShowCreate] = useState(false)
  const [createForm, setCreateForm] = useState({ username: '', password: '', display_name: '', email: '' })
  const [creating, setCreating] = useState(false)

  // Reset password modal states
  const [resetTarget, setResetTarget] = useState<User | null>(null)
  const [newPassword, setNewPassword] = useState('')
  const [resetting, setResetting] = useState(false)

  // Edit modal states
  const [editTarget, setEditTarget] = useState<User | null>(null)
  const [editForm, setEditForm] = useState({ display_name: '', email: '', phone: '', status: 1 })
  const [editLoading, setEditLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [delUser, setDelUser] = useState<User | null>(null)
  const [deletingUser, setDeletingUser] = useState(false)

  // Restore modal state
  const [restoreTarget, setRestoreTarget] = useState<User | null>(null)
  const [restoring, setRestoring] = useState(false)

  const loadData = useCallback(async () => {
    setLoading(true)
    try {
      const params: Record<string, unknown> = { page: q.page, page_size: 20 }
      if (q.search) params.search = q.search
      if (q.status !== '') params.status = Number(q.status)
      if (q.showDeleted === '1') params.include_deleted = true
      const result = await userApi.list(params)
      setData(result)
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }, [q.page, q.search, q.status, q.showDeleted])

  useEffect(() => {
    void loadData()
  }, [loadData])

  const handleSearchChange = (val: string) => {
    setSearch(val)
    if (timerRef.current) clearTimeout(timerRef.current)
    timerRef.current = setTimeout(() => {
      setQ({ search: val, page: 1 })
    }, 400)
  }

  const handleStatusChange = async (user: User, newStatus: number) => {
    try {
      await userApi.updateStatus(user.id, newStatus)
      toast.success(t('common.success'))
      loadData()
    } catch (e) {
      toast.error(t('common.failed'), extractMessage(e))
    }
  }

  const confirmDeleteUser = async () => {
    if (!delUser) return
    setDeletingUser(true)
    try {
      await userApi.delete(delUser.id)
      toast.success(t('common.success'))
      setDelUser(null)
      loadData()
    } catch (e) {
      toast.error(t('common.failed'), extractMessage(e))
    } finally {
      setDeletingUser(false)
    }
  }

  const confirmRestoreUser = async () => {
    if (!restoreTarget) return
    setRestoring(true)
    try {
      await userApi.restoreUser(restoreTarget.id)
      toast.success(t('users.list.restoreUserSuccess'))
      setRestoreTarget(null)
      loadData()
    } catch (e) {
      toast.error(t('users.list.restoreUserFailed'), extractMessage(e))
    } finally {
      setRestoring(false)
    }
  }

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!createForm.username || !createForm.password) return
    setCreating(true)
    try {
      await userApi.create({
        username: createForm.username,
        password: createForm.password,
        display_name: createForm.display_name || undefined,
        email: createForm.email || undefined,
      })
      setShowCreate(false)
      setCreateForm({ username: '', password: '', display_name: '', email: '' })
      setQ({ page: 1 })
      loadData()
      toast.success(t('common.success'))
    } catch (e) {
      toast.error(t('common.failed'), extractMessage(e))
    } finally {
      setCreating(false)
    }
  }

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!resetTarget || !newPassword) return
    setResetting(true)
    try {
      await userApi.resetPassword(resetTarget.id, newPassword)
      setResetTarget(null)
      setNewPassword('')
      toast.success(t('common.success'))
    } catch (e) {
      toast.error(t('common.failed'), extractMessage(e))
    } finally {
      setResetting(false)
    }
  }

  const openEditModal = async (user: User) => {
    setEditTarget(user)
    setEditForm({
      display_name: user.display_name || '',
      email: user.email || '',
      phone: user.phone || '',
      status: user.status,
    })
    setEditLoading(true)
    try {
      const fresh = await userApi.getById(user.id)
      setEditTarget(fresh)
      setEditForm({
        display_name: fresh.display_name || '',
        email: fresh.email || '',
        phone: fresh.phone || '',
        status: fresh.status,
      })
    } catch {
      // fall back to list data already set above
    } finally {
      setEditLoading(false)
    }
  }

  const handleEdit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!editTarget) return
    setSaving(true)
    try {
      const payload: UpdateUserRequest = {
        display_name: editForm.display_name || undefined,
        email: editForm.email || undefined,
        phone: editForm.phone || undefined,
        status: editForm.status,
      }
      await userApi.update(editTarget.id, payload)
      toast.success(t('common.success'))
      setEditTarget(null)
      loadData()
    } catch (e) {
      toast.error(t('common.failed'), extractMessage(e))
    } finally {
      setSaving(false)
    }
  }

  // Column config for the shared DataTable. Row click navigates to detail; the
  // actions cell stops propagation so its buttons don't trigger the nav.
  const columns: Column<User>[] = [
    {
      key: 'username',
      title: t('users.columns.username'),
      render: (u) => (
        <div className={cn('flex items-center gap-2.5', u.deleted_at && 'opacity-50')}>
          {u.avatar ? (
            <img src={u.avatar} alt={u.username} className="h-7 w-7 shrink-0 rounded-full object-cover" />
          ) : (
            <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-primary/15 text-xs font-medium uppercase text-primary">
              {(u.display_name || u.username).charAt(0)}
            </span>
          )}
          <span className="font-medium text-primary hover:underline">{u.username}</span>
        </div>
      ),
    },
    {
      key: 'display_name',
      title: t('users.columns.displayName'),
      render: (u) => <span className={cn('text-muted', u.deleted_at && 'opacity-50')}>{u.display_name || '-'}</span>,
    },
    {
      key: 'email',
      title: t('users.columns.email'),
      render: (u) => <span className={cn('text-muted', u.deleted_at && 'opacity-50')}>{u.email || '-'}</span>,
    },
    {
      key: 'status',
      title: t('users.columns.status'),
      render: (u) =>
        u.deleted_at ? (
          <span className="text-sm font-medium text-red-500 opacity-50">{t('users.list.deleted')}</span>
        ) : (
          <span className={cn('text-sm font-medium', statusColor(u.status))}>{statusLabel(u.status)}</span>
        ),
    },
    {
      key: 'mfa',
      title: t('users.columns.mfa'),
      render: (u) =>
        u.mfa_enabled ? (
          <span className={cn('inline-flex items-center gap-1 text-xs font-medium text-emerald-600', u.deleted_at && 'opacity-50')}>
            <ShieldCheck className="h-3.5 w-3.5" /> {t('users.mfa.on')}
          </span>
        ) : (
          <span className={cn('inline-flex items-center gap-1 text-xs text-faint', u.deleted_at && 'opacity-50')}>
            <ShieldOff className="h-3.5 w-3.5" /> {t('users.mfa.off')}
          </span>
        ),
    },
    {
      key: 'last_login',
      title: t('users.columns.lastLogin'),
      render: (u) => <span className={cn('whitespace-nowrap text-muted', u.deleted_at && 'opacity-50')}>{formatDate(u.last_login_at)}</span>,
    },
    {
      key: 'created_at',
      title: t('users.columns.createdAt'),
      render: (u) => <span className={cn('whitespace-nowrap text-muted', u.deleted_at && 'opacity-50')}>{formatDate(u.created_at)}</span>,
    },
    {
      key: 'actions',
      title: t('common.actions'),
      align: 'right',
      render: (u) =>
        u.deleted_at ? (
          <div className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()}>
            <button
              onClick={() => setRestoreTarget(u)}
              className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs text-faint hover:bg-surface-muted hover:text-ink"
              title={t('users.list.restoreUser')}
            >
              <Undo2 className="h-3.5 w-3.5" />
              {t('users.list.restoreUser')}
            </button>
          </div>
        ) : (
          <div className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()}>
            <button
              onClick={() => openEditModal(u)}
              className="rounded p-1 text-faint hover:bg-blue-50 hover:text-blue-500"
              title={t('common.edit')}
            >
              <Pencil className="h-3.5 w-3.5" />
            </button>
            {u.status === UserStatus.Active ? (
              <button
                onClick={() => handleStatusChange(u, 3)}
                className="rounded px-2 py-1 text-xs text-muted hover:bg-surface-muted hover:text-ink"
              >
                {t('common.disable')}
              </button>
            ) : (
              <button
                onClick={() => handleStatusChange(u, 1)}
                className="rounded px-2 py-1 text-xs text-emerald-600 hover:bg-emerald-50"
              >
                {t('common.enable')}
              </button>
            )}
            <button
              onClick={() => setResetTarget(u)}
              className="rounded p-1 text-faint hover:bg-surface-muted hover:text-muted"
              title={t('users.resetPassword')}
            >
              <RotateCcw className="h-3.5 w-3.5" />
            </button>
            <button
              onClick={() => setDelUser(u)}
              className="rounded p-1 text-faint hover:bg-red-50 hover:text-red-500"
              title={t('common.delete')}
            >
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          </div>
        ),
    },
  ]

  return (
    <motion.div {...pageMotion}>
      <PageHeader
        title={t('users.title')}
        description={t('users.subtitle')}
        actions={
          <Button onClick={() => setShowCreate(true)} icon={<Plus className="h-4 w-4" />}>
            {t('users.create')}
          </Button>
        }
      />

      <div className="space-y-4">
        <FilterBar>
          <SearchInput
            value={search}
            onChange={handleSearchChange}
            placeholder={t('common.search')}
            className="max-w-xs flex-1"
          />
          <Select
            value={q.status}
            onChange={(e) => setQ({ status: e.target.value, page: 1 })}
            className="w-auto"
          >
            <option value="">{t('common.all')}</option>
            <option value={1}>{t('users.statusActive')}</option>
            <option value={2}>{t('users.statusLocked')}</option>
            <option value={3}>{t('users.statusDisabled')}</option>
            <option value={4}>{t('users.statusPending')}</option>
          </Select>
          <label className="flex items-center gap-2 text-sm text-muted">
            <input
              type="checkbox"
              checked={q.showDeleted === '1'}
              onChange={(e) => setQ({ showDeleted: e.target.checked ? '1' : '0', page: 1 })}
              className="h-4 w-4 rounded border-border"
            />
            {t('users.list.showDeleted')}
          </label>
        </FilterBar>

        <Card className="overflow-hidden hover:shadow-card">
          <DataTable
            columns={columns}
            rows={data.items}
            rowKey={(u) => u.id}
            loading={loading}
            onRowClick={(u) => navigate(`/users/${u.id}`)}
          />
          {data.total > 0 && (
            <div className="border-t border-border">
              <Pagination page={q.page} pageSize={data.page_size} total={data.total} onChange={(p) => setQ({ page: p })} />
            </div>
          )}
        </Card>
      </div>

      {/* Create User Modal */}
      <Modal open={showCreate} title={t('users.list.createModal.title')} onClose={() => setShowCreate(false)}>
            <form onSubmit={handleCreate} className="space-y-4">
              <Field
                label={t('users.list.createModal.username')}
                required hint={<>{t('users.list.createModal.usernameHintPrefix')}<code className="rounded bg-surface-muted px-1">zhangsan</code>{t('users.list.createModal.usernameHintMid')}<span className="text-amber-600">{t('users.list.createModal.usernameHintImmutable')}</span></>}
              >
                <input
                  type="text"
                  value={createForm.username}
                  onChange={(e) => setCreateForm((f) => ({ ...f, username: e.target.value }))}
                  className="w-full rounded-lg border border-border px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                  required
                />
              </Field>
              <Field
                label={t('users.list.createModal.password')}
                required hint={t('users.list.createModal.passwordHint')}
              >
                <input
                  type="password"
                  value={createForm.password}
                  onChange={(e) => setCreateForm((f) => ({ ...f, password: e.target.value }))}
                  className="w-full rounded-lg border border-border px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                  required
                />
              </Field>
              <Field
                label={t('users.list.createModal.displayName')}
                hint={t('users.list.createModal.displayNameHint')}
              >
                <input
                  type="text"
                  value={createForm.display_name}
                  onChange={(e) => setCreateForm((f) => ({ ...f, display_name: e.target.value }))}
                  className="w-full rounded-lg border border-border px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                />
              </Field>
              <Field label={t('users.list.createModal.email')} hint={t('users.list.createModal.emailHint')}>
                <input
                  type="email"
                  value={createForm.email}
                  onChange={(e) => setCreateForm((f) => ({ ...f, email: e.target.value }))}
                  className="w-full rounded-lg border border-border px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                />
              </Field>
              <div className="flex justify-end gap-3 pt-2">
                <Button type="button" variant="secondary" onClick={() => setShowCreate(false)}>
                  {t('users.list.createModal.cancel')}
                </Button>
                <Button type="submit" loading={creating}>
                  {t('users.list.createModal.submit')}
                </Button>
              </div>
            </form>
      </Modal>

      {/* Reset Password Modal */}
      <Modal
        open={!!resetTarget}
        title={resetTarget ? t('users.list.resetModal.title', { username: resetTarget.username }) : ''}
        onClose={() => { setResetTarget(null); setNewPassword('') }}
        size="sm"
      >
        {resetTarget && (
            <form onSubmit={handleResetPassword} className="space-y-4">
              <Field
                label={t('users.list.resetModal.newPassword')}
                required hint={t('users.list.resetModal.newPasswordHint')}
              >
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full rounded-lg border border-border px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                  required
                  autoFocus
                />
              </Field>
              <div className="flex justify-end gap-3 pt-2">
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => {
                    setResetTarget(null)
                    setNewPassword('')
                  }}
                >
                  {t('users.list.resetModal.cancel')}
                </Button>
                <Button type="submit" loading={resetting}>
                  {t('users.list.resetModal.submit')}
                </Button>
              </div>
            </form>
        )}
      </Modal>

      {/* Edit User Modal */}
      <Modal open={!!editTarget} title={t('users.list.editModal.title')} onClose={() => setEditTarget(null)}>
            {editLoading ? (
              <div className="flex items-center justify-center py-10">
                <Loader2 className="h-6 w-6 animate-spin text-primary" />
              </div>
            ) : editTarget ? (
              <form onSubmit={handleEdit} className="space-y-4">
                <Field
                  label={t('users.list.editModal.username')}
                  hint={<>{t('users.list.editModal.usernameHintPrefix')}<span className="text-amber-600">{t('users.list.editModal.usernameHintImmutable')}</span></>}
                >
                  <input
                    type="text"
                    value={editTarget.username}
                    disabled
                    className="w-full rounded-lg border border-border bg-surface-muted px-3 py-2 text-sm text-muted outline-none"
                  />
                </Field>
                <Field
                  label={t('users.list.editModal.displayName')}
                  hint={t('users.list.editModal.displayNameHint')}
                >
                  <input
                    type="text"
                    value={editForm.display_name}
                    onChange={(e) => setEditForm((f) => ({ ...f, display_name: e.target.value }))}
                    placeholder={t('users.list.editModal.displayNamePlaceholder')}
                    className="w-full rounded-lg border border-border px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                  />
                </Field>
                <Field label={t('users.list.editModal.email')} hint={t('users.list.editModal.emailHint')}>
                  <input
                    type="email"
                    value={editForm.email}
                    onChange={(e) => setEditForm((f) => ({ ...f, email: e.target.value }))}
                    placeholder={t('users.list.editModal.emailPlaceholder')}
                    className="w-full rounded-lg border border-border px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                  />
                </Field>
                <Field label={t('users.list.editModal.phone')} hint={t('users.list.editModal.phoneHint')}>
                  <input
                    type="tel"
                    value={editForm.phone}
                    onChange={(e) => setEditForm((f) => ({ ...f, phone: e.target.value }))}
                    placeholder={t('users.list.editModal.phonePlaceholder')}
                    className="w-full rounded-lg border border-border px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                  />
                </Field>
                <Field
                  label={t('users.list.editModal.status')}
                  hint={<><strong>{t('users.list.editModal.statusActive')}</strong>{t('users.list.editModal.statusHintActiveDesc')}<strong>{t('users.list.editModal.statusLocked')}</strong>{t('users.list.editModal.statusHintLockedDesc')}<strong>{t('users.list.editModal.statusDisabled')}</strong>{t('users.list.editModal.statusHintDisabledDesc')}<strong>{t('users.list.editModal.statusPending')}</strong>{t('users.list.editModal.statusHintPendingDesc')}</>}
                >
                  <select
                    value={editForm.status}
                    onChange={(e) => setEditForm((f) => ({ ...f, status: Number(e.target.value) }))}
                    className="w-full rounded-lg border border-border bg-surface text-ink px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                  >
                    <option value={1}>{t('users.list.editModal.statusActive')}</option>
                    <option value={2}>{t('users.list.editModal.statusLocked')}</option>
                    <option value={3}>{t('users.list.editModal.statusDisabled')}</option>
                    <option value={4}>{t('users.list.editModal.statusPending')}</option>
                  </select>
                </Field>
                <div className="flex justify-end gap-3 pt-2">
                  <Button type="button" variant="secondary" onClick={() => setEditTarget(null)}>
                    {t('users.list.editModal.cancel')}
                  </Button>
                  <Button type="submit" loading={saving}>
                    {t('users.list.editModal.submit')}
                  </Button>
                </div>
              </form>
            ) : null}
      </Modal>

      <ConfirmDialog
        open={!!delUser}
        title={t('users.list.confirmDelete', { name: delUser?.username ?? '' })}
        desc={t('common.cantUndo')}
        loading={deletingUser}
        onConfirm={confirmDeleteUser}
        onCancel={() => setDelUser(null)}
      />

      <ConfirmDialog
        open={!!restoreTarget}
        title={t('users.list.confirmRestoreUser', { username: restoreTarget?.username ?? '' })}
        danger={false}
        loading={restoring}
        onConfirm={confirmRestoreUser}
        onCancel={() => setRestoreTarget(null)}
      />
    </motion.div>
  )
}
