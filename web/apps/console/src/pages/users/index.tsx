import { useEffect, useState, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Plus, Search, RotateCcw, Trash2, Loader2, Pencil, X } from 'lucide-react'
import { userApi, formatDate, statusLabel, statusColor, cn, useTranslation } from '@mxid/shared'
import type { User, PaginatedData, UpdateUserRequest } from '@mxid/shared'
import PageHeader from '../../components/layout/PageHeader'
import { toast, extractMessage } from '../../components/ui/toast'

export default function UsersPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [data, setData] = useState<PaginatedData<User>>({ items: [], total: 0, page: 1, page_size: 20 })
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<number | ''>('')
  const [page, setPage] = useState(1)
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

  const loadData = useCallback(async () => {
    setLoading(true)
    try {
      const params: Record<string, unknown> = { page, page_size: 20 }
      if (search) params.keyword = search
      if (statusFilter !== '') params.status = statusFilter
      const result = await userApi.list(params)
      setData(result)
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }, [page, search, statusFilter])

  useEffect(() => {
    void loadData()
  }, [loadData])

  const handleSearchChange = (val: string) => {
    setSearch(val)
    if (timerRef.current) clearTimeout(timerRef.current)
    timerRef.current = setTimeout(() => {
      setPage(1)
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

  const handleDelete = async (user: User) => {
    if (!confirm(t('users.list.confirmDelete', { name: user.username }))) return
    try {
      await userApi.delete(user.id)
      toast.success(t('common.success'))
      loadData()
    } catch (e) {
      toast.error(t('common.failed'), extractMessage(e))
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
      setPage(1)
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

  const totalPages = Math.ceil(data.total / data.page_size) || 1

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.3 }}>
      <PageHeader
        title={t('users.title')}
        description={t('users.subtitle')}
        actions={
          <button
            onClick={() => setShowCreate(true)}
            className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-primary-hover"
          >
            <Plus className="h-4 w-4" />
            {t('users.create')}
          </button>
        }
      />

      {/* Filters */}
      <div className="mb-4 flex items-center gap-4">
        <div className="relative max-w-xs flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
          <input
            type="text"
            value={search}
            onChange={(e) => handleSearchChange(e.target.value)}
            placeholder={t('common.search')}
            className="w-full rounded-lg border border-gray-200 py-2 pl-10 pr-4 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
          />
        </div>
        <select
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value === '' ? '' : Number(e.target.value))
            setPage(1)
          }}
          className="rounded-lg border border-gray-200 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
        >
          <option value="">{t('common.all')}</option>
          <option value={1}>{t('users.statusActive')}</option>
          <option value={2}>{t('users.statusLocked')}</option>
          <option value={3}>{t('users.statusDisabled')}</option>
          <option value={4}>{t('users.statusPending')}</option>
        </select>
      </div>

      {/* Table */}
      <div className="rounded-xl border border-gray-100 bg-white shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-100 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                <th className="px-6 py-3">{t('users.columns.username')}</th>
                <th className="px-6 py-3">{t('users.columns.displayName')}</th>
                <th className="px-6 py-3">{t('users.columns.email')}</th>
                <th className="px-6 py-3">{t('users.columns.status')}</th>
                <th className="px-6 py-3">{t('users.columns.lastLogin')}</th>
                <th className="px-6 py-3">{t('users.columns.createdAt')}</th>
                <th className="px-6 py-3 text-right">{t('common.actions')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {loading ? (
                <tr>
                  <td colSpan={7} className="px-6 py-10 text-center text-sm text-gray-400">
{t('common.loading')}
                  </td>
                </tr>
              ) : data.items.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-6 py-10 text-center text-sm text-gray-400">
{t('common.empty')}
                  </td>
                </tr>
              ) : (
                data.items.map((user) => (
                  <tr
                    key={user.id}
                    className="cursor-pointer hover:bg-gray-50/50"
                    onClick={() => navigate(`/users/${user.id}`)}
                  >
                    <td className="px-6 py-3 text-sm font-medium text-primary hover:underline">
                      {user.username}
                    </td>
                    <td className="px-6 py-3 text-sm text-gray-600">
                      {user.display_name || '-'}
                    </td>
                    <td className="px-6 py-3 text-sm text-gray-600">
                      {user.email || '-'}
                    </td>
                    <td className="px-6 py-3">
                      <span className={cn('text-sm font-medium', statusColor(user.status))}>
                        {statusLabel(user.status)}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-6 py-3 text-sm text-gray-500">
                      {formatDate(user.last_login_at)}
                    </td>
                    <td className="whitespace-nowrap px-6 py-3 text-sm text-gray-500">
                      {formatDate(user.created_at)}
                    </td>
                    <td className="px-6 py-3 text-right">
                      <div className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={() => openEditModal(user)}
                          className="rounded p-1 text-gray-400 hover:bg-blue-50 hover:text-blue-500"
                          title={t('common.edit')}
                        >
                          <Pencil className="h-3.5 w-3.5" />
                        </button>
                        {user.status === 1 ? (
                          <button
                            onClick={() => handleStatusChange(user, 3)}
                            className="rounded px-2 py-1 text-xs text-gray-500 hover:bg-gray-100 hover:text-gray-700"
                          >
{t('common.disable')}
                          </button>
                        ) : (
                          <button
                            onClick={() => handleStatusChange(user, 1)}
                            className="rounded px-2 py-1 text-xs text-green-600 hover:bg-green-50"
                          >
{t('common.enable')}
                          </button>
                        )}
                        <button
                          onClick={() => setResetTarget(user)}
                          className="rounded p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-600"
                          title={t('users.resetPassword')}
                        >
                          <RotateCcw className="h-3.5 w-3.5" />
                        </button>
                        <button
                          onClick={() => handleDelete(user)}
                          className="rounded p-1 text-gray-400 hover:bg-red-50 hover:text-red-500"
                          title={t('common.delete')}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {data.total > 0 && (
          <div className="flex items-center justify-between border-t border-gray-100 px-6 py-3">
            <p className="text-sm text-gray-500">
              {t('users.list.pagingSummary', { total: data.total, page, pages: totalPages })}
            </p>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="rounded-lg border border-gray-200 px-3 py-1.5 text-sm disabled:opacity-40 hover:bg-gray-50"
              >
                {t('users.list.prevPage')}
              </button>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="rounded-lg border border-gray-200 px-3 py-1.5 text-sm disabled:opacity-40 hover:bg-gray-50"
              >
                {t('users.list.nextPage')}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Create User Modal */}
      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="w-full max-w-md rounded-xl bg-white p-6 shadow-xl"
          >
            <h3 className="mb-4 text-lg font-semibold">{t('users.list.createModal.title')}</h3>
            <form onSubmit={handleCreate} className="space-y-4">
              <div>
                <label className="mb-1 block text-sm font-medium text-gray-700">{t('users.list.createModal.username')}</label>
                <input
                  type="text"
                  value={createForm.username}
                  onChange={(e) => setCreateForm((f) => ({ ...f, username: e.target.value }))}
                  className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                  required
                />
                <p className="mt-1 text-xs text-gray-400">
                  {t('users.list.createModal.usernameHintPrefix')}<code className="rounded bg-gray-100 px-1">zhangsan</code>{t('users.list.createModal.usernameHintMid')}<span className="text-amber-600">{t('users.list.createModal.usernameHintImmutable')}</span>
                </p>
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-gray-700">{t('users.list.createModal.password')}</label>
                <input
                  type="password"
                  value={createForm.password}
                  onChange={(e) => setCreateForm((f) => ({ ...f, password: e.target.value }))}
                  className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                  required
                />
                <p className="mt-1 text-xs text-gray-400">{t('users.list.createModal.passwordHint')}</p>
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-gray-700">{t('users.list.createModal.displayName')}</label>
                <input
                  type="text"
                  value={createForm.display_name}
                  onChange={(e) => setCreateForm((f) => ({ ...f, display_name: e.target.value }))}
                  className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                />
                <p className="mt-1 text-xs text-gray-400">{t('users.list.createModal.displayNameHint')}</p>
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-gray-700">{t('users.list.createModal.email')}</label>
                <input
                  type="email"
                  value={createForm.email}
                  onChange={(e) => setCreateForm((f) => ({ ...f, email: e.target.value }))}
                  className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                />
                <p className="mt-1 text-xs text-gray-400">{t('users.list.createModal.emailHint')}</p>
              </div>
              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreate(false)}
                  className="rounded-lg border border-gray-200 px-4 py-2 text-sm hover:bg-gray-50"
                >
                  {t('users.list.createModal.cancel')}
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-60"
                >
                  {creating && <Loader2 className="h-4 w-4 animate-spin" />}
                  {t('users.list.createModal.submit')}
                </button>
              </div>
            </form>
          </motion.div>
        </div>
      )}

      {/* Reset Password Modal */}
      {resetTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="w-full max-w-sm rounded-xl bg-white p-6 shadow-xl"
          >
            <h3 className="mb-4 text-lg font-semibold">
              {t('users.list.resetModal.title', { username: resetTarget.username })}
            </h3>
            <form onSubmit={handleResetPassword} className="space-y-4">
              <div>
                <label className="mb-1 block text-sm font-medium text-gray-700">{t('users.list.resetModal.newPassword')}</label>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                  required
                  autoFocus
                />
                <p className="mt-1 text-xs text-gray-400">{t('users.list.resetModal.newPasswordHint')}</p>
              </div>
              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => {
                    setResetTarget(null)
                    setNewPassword('')
                  }}
                  className="rounded-lg border border-gray-200 px-4 py-2 text-sm hover:bg-gray-50"
                >
                  {t('users.list.resetModal.cancel')}
                </button>
                <button
                  type="submit"
                  disabled={resetting}
                  className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-60"
                >
                  {resetting && <Loader2 className="h-4 w-4 animate-spin" />}
                  {t('users.list.resetModal.submit')}
                </button>
              </div>
            </form>
          </motion.div>
        </div>
      )}

      {/* Edit User Modal */}
      {editTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40" onClick={() => setEditTarget(null)}>
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="w-full max-w-md rounded-xl bg-white p-6 shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-4 flex items-center justify-between">
              <h3 className="text-lg font-semibold">{t('users.list.editModal.title')}</h3>
              <button
                onClick={() => setEditTarget(null)}
                className="rounded p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-600"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {editLoading ? (
              <div className="flex items-center justify-center py-10">
                <Loader2 className="h-6 w-6 animate-spin text-primary" />
              </div>
            ) : (
              <form onSubmit={handleEdit} className="space-y-4">
                <div>
                  <label className="mb-1 block text-sm font-medium text-gray-700">{t('users.list.editModal.username')}</label>
                  <input
                    type="text"
                    value={editTarget.username}
                    disabled
                    className="w-full rounded-lg border border-gray-200 bg-gray-50 px-3 py-2 text-sm text-gray-500 outline-none"
                  />
                  <p className="mt-1 text-xs text-gray-400">{t('users.list.editModal.usernameHintPrefix')}<span className="text-amber-600">{t('users.list.editModal.usernameHintImmutable')}</span></p>
                </div>
                <div>
                  <label className="mb-1 block text-sm font-medium text-gray-700">{t('users.list.editModal.displayName')}</label>
                  <input
                    type="text"
                    value={editForm.display_name}
                    onChange={(e) => setEditForm((f) => ({ ...f, display_name: e.target.value }))}
                    placeholder={t('users.list.editModal.displayNamePlaceholder')}
                    className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                  />
                  <p className="mt-1 text-xs text-gray-400">{t('users.list.editModal.displayNameHint')}</p>
                </div>
                <div>
                  <label className="mb-1 block text-sm font-medium text-gray-700">{t('users.list.editModal.email')}</label>
                  <input
                    type="email"
                    value={editForm.email}
                    onChange={(e) => setEditForm((f) => ({ ...f, email: e.target.value }))}
                    placeholder={t('users.list.editModal.emailPlaceholder')}
                    className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                  />
                  <p className="mt-1 text-xs text-gray-400">{t('users.list.editModal.emailHint')}</p>
                </div>
                <div>
                  <label className="mb-1 block text-sm font-medium text-gray-700">{t('users.list.editModal.phone')}</label>
                  <input
                    type="tel"
                    value={editForm.phone}
                    onChange={(e) => setEditForm((f) => ({ ...f, phone: e.target.value }))}
                    placeholder={t('users.list.editModal.phonePlaceholder')}
                    className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                  />
                  <p className="mt-1 text-xs text-gray-400">{t('users.list.editModal.phoneHint')}</p>
                </div>
                <div>
                  <label className="mb-1 block text-sm font-medium text-gray-700">{t('users.list.editModal.status')}</label>
                  <select
                    value={editForm.status}
                    onChange={(e) => setEditForm((f) => ({ ...f, status: Number(e.target.value) }))}
                    className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
                  >
                    <option value={1}>{t('users.list.editModal.statusActive')}</option>
                    <option value={2}>{t('users.list.editModal.statusLocked')}</option>
                    <option value={3}>{t('users.list.editModal.statusDisabled')}</option>
                    <option value={4}>{t('users.list.editModal.statusPending')}</option>
                  </select>
                  <p className="mt-1 text-xs text-gray-400">
                    <strong>{t('users.list.editModal.statusActive')}</strong>{t('users.list.editModal.statusHintActiveDesc')}<strong>{t('users.list.editModal.statusLocked')}</strong>{t('users.list.editModal.statusHintLockedDesc')}<strong>{t('users.list.editModal.statusDisabled')}</strong>{t('users.list.editModal.statusHintDisabledDesc')}<strong>{t('users.list.editModal.statusPending')}</strong>{t('users.list.editModal.statusHintPendingDesc')}
                  </p>
                </div>
                <div className="flex justify-end gap-3 pt-2">
                  <button
                    type="button"
                    onClick={() => setEditTarget(null)}
                    className="rounded-lg border border-gray-200 px-4 py-2 text-sm hover:bg-gray-50"
                  >
                    {t('users.list.editModal.cancel')}
                  </button>
                  <button
                    type="submit"
                    disabled={saving}
                    className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-60"
                  >
                    {saving && <Loader2 className="h-4 w-4 animate-spin" />}
                    {t('users.list.editModal.submit')}
                  </button>
                </div>
              </form>
            )}
          </motion.div>
        </div>
      )}
    </motion.div>
  )
}
