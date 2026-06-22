// AccessEligibility — JIT privileged access eligibility policy config.
//
// Gated on the `conditional_access` EE feature at the page level (mirrors
// the pattern in access-approvals/index.tsx). The API itself also 403s in CE,
// so this is defence-in-depth.
import { useCallback, useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { accessApprovalApi, useTranslation, useEdition } from '@mxid/shared'
import type { Eligibility, CreateEligibilityBody } from '@mxid/shared'
import { pageMotion, Button, Field, Input } from '@mxid/shared/ui'
import { toast, extractMessage } from '../../components/ui/toast'

const ALL_DURATIONS = [3600, 14400, 86400, 259200, 604800] as const
const DURATION_LABELS: Record<number, string> = {
  3600: '1h',
  14400: '4h',
  86400: '24h',
  259200: '72h',
  604800: '7d',
}

const DEFAULT_FORM: CreateEligibilityBody = {
  target_kind: 'app',
  role_id: '',
  app_id: '',
  requester_subject_type: 'group',
  requester_subject_id: '',
  allowed_durations: [3600, 14400],
  max_duration_seconds: 86400,
  approver_subject_type: 'role',
  approver_subject_id: '',
  require_justification: false,
  require_stepup: false,
}

export default function AccessEligibilityPage() {
  const { t } = useTranslation()
  const edition = useEdition()
  const [rows, setRows] = useState<Eligibility[]>([])
  const [loading, setLoading] = useState(true)
  const [form, setForm] = useState<CreateEligibilityBody>(DEFAULT_FORM)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setRows((await accessApprovalApi.listEligibilities()) ?? [])
    } catch (e) {
      toast.error(t('eligibility.loadFailed'), extractMessage(e))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    void load()
  }, [load])

  const toggleDuration = (d: number) =>
    setForm((f) => ({
      ...f,
      allowed_durations: f.allowed_durations.includes(d)
        ? f.allowed_durations.filter((x) => x !== d)
        : [...f.allowed_durations, d],
    }))

  const create = async () => {
    if (!form.role_id.trim()) {
      toast.error(t('eligibility.createFailed'), t('eligibility.roleIdRequired'))
      return
    }
    try {
      const body: CreateEligibilityBody = {
        ...form,
        // omit app_id when target is console
        app_id: form.target_kind === 'app' ? form.app_id : undefined,
      }
      await accessApprovalApi.createEligibility(body)
      toast.success(t('eligibility.created'))
      setForm(DEFAULT_FORM)
      void load()
    } catch (e) {
      toast.error(t('eligibility.createFailed'), extractMessage(e))
    }
  }

  const remove = async (id: string) => {
    if (!confirm(t('eligibility.confirmDelete'))) return
    try {
      await accessApprovalApi.deleteEligibility(id)
      toast.success(t('eligibility.deleted'))
      void load()
    } catch (e) {
      toast.error(t('eligibility.deleteFailed'), extractMessage(e))
    }
  }

  if (!edition.has('conditional_access')) {
    return (
      <motion.div {...pageMotion} className="p-6">
        <p className="text-gray-500">{t('eligibility.featureDisabled')}</p>
      </motion.div>
    )
  }

  return (
    <motion.div {...pageMotion} className="space-y-6">
      {/* Create form */}
      <section className="rounded-xl border border-gray-200 bg-white p-6">
        <div className="mb-4">
          <h2 className="text-lg font-semibold text-gray-900">{t('eligibility.createTitle')}</h2>
          <p className="mt-0.5 text-sm text-gray-500">{t('eligibility.createDesc')}</p>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <Field label={t('eligibility.targetKind')}>
            <select
              className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
              value={form.target_kind}
              onChange={(e) =>
                setForm((f) => ({
                  ...f,
                  target_kind: e.target.value as 'console' | 'app',
                }))
              }
            >
              <option value="app">{t('access.targetApp')}</option>
              <option value="console">{t('access.targetConsole')}</option>
            </select>
          </Field>

          <Field label={t('eligibility.roleId')}>
            <Input
              placeholder={t('eligibility.roleIdPlaceholder')}
              value={form.role_id}
              onChange={(e) => setForm((f) => ({ ...f, role_id: e.target.value }))}
            />
          </Field>

          {form.target_kind === 'app' && (
            <Field label={t('eligibility.appId')}>
              <Input
                placeholder={t('eligibility.appIdPlaceholder')}
                value={form.app_id ?? ''}
                onChange={(e) => setForm((f) => ({ ...f, app_id: e.target.value }))}
              />
            </Field>
          )}

          <Field label={t('eligibility.requesterGroupId')}>
            <Input
              placeholder={t('eligibility.requesterGroupIdPlaceholder')}
              value={form.requester_subject_id ?? ''}
              onChange={(e) =>
                setForm((f) => ({ ...f, requester_subject_id: e.target.value }))
              }
            />
          </Field>

          <Field label={t('eligibility.approverRoleId')}>
            <Input
              placeholder={t('eligibility.approverRoleIdPlaceholder')}
              value={form.approver_subject_id ?? ''}
              onChange={(e) =>
                setForm((f) => ({ ...f, approver_subject_id: e.target.value }))
              }
            />
          </Field>

          <Field label={t('eligibility.maxDuration')}>
            <select
              className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20"
              value={form.max_duration_seconds}
              onChange={(e) =>
                setForm((f) => ({
                  ...f,
                  max_duration_seconds: Number(e.target.value),
                }))
              }
            >
              {ALL_DURATIONS.map((d) => (
                <option key={d} value={d}>
                  {DURATION_LABELS[d]}
                </option>
              ))}
            </select>
          </Field>

          <div className="md:col-span-2">
            <div className="mb-1.5 text-sm font-medium text-gray-700">
              {t('eligibility.allowedDurations')}
            </div>
            <div className="flex flex-wrap gap-4">
              {ALL_DURATIONS.map((d) => (
                <label key={d} className="flex cursor-pointer items-center gap-1.5 text-sm text-gray-700">
                  <input
                    type="checkbox"
                    className="h-4 w-4 rounded border-gray-300"
                    checked={form.allowed_durations.includes(d)}
                    onChange={() => toggleDuration(d)}
                  />
                  {DURATION_LABELS[d]}
                </label>
              ))}
            </div>
          </div>

          <div className="flex flex-wrap gap-6 md:col-span-2">
            <label className="flex cursor-pointer items-center gap-2 text-sm text-gray-700">
              <input
                type="checkbox"
                className="h-4 w-4 rounded border-gray-300"
                checked={form.require_justification ?? false}
                onChange={(e) =>
                  setForm((f) => ({ ...f, require_justification: e.target.checked }))
                }
              />
              {t('eligibility.requireJustification')}
            </label>
            <label className="flex cursor-pointer items-center gap-2 text-sm text-gray-700">
              <input
                type="checkbox"
                className="h-4 w-4 rounded border-gray-300"
                checked={form.require_stepup ?? false}
                onChange={(e) =>
                  setForm((f) => ({ ...f, require_stepup: e.target.checked }))
                }
              />
              {t('eligibility.requireStepup')}
            </label>
          </div>
        </div>

        <div className="mt-5 flex justify-end">
          <Button onClick={create}>{t('eligibility.create')}</Button>
        </div>
      </section>

      {/* Eligibility list */}
      <section className="rounded-xl border border-gray-200 bg-white">
        <div className="border-b border-gray-100 px-6 py-4">
          <h2 className="text-base font-semibold text-gray-900">{t('eligibility.listTitle')}</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-100 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                <th className="px-6 py-3">{t('eligibility.columns.target')}</th>
                <th className="px-6 py-3">{t('eligibility.columns.role')}</th>
                <th className="px-6 py-3">{t('eligibility.columns.requester')}</th>
                <th className="px-6 py-3">{t('eligibility.columns.approver')}</th>
                <th className="px-6 py-3">{t('eligibility.columns.durations')}</th>
                <th className="px-6 py-3 text-right">{t('common.actions')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {loading ? (
                <tr>
                  <td colSpan={6} className="px-6 py-10 text-center text-sm text-gray-400">
                    {t('common.loading')}
                  </td>
                </tr>
              ) : rows.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-10 text-center text-sm text-gray-400">
                    {t('eligibility.empty')}
                  </td>
                </tr>
              ) : (
                rows.map((row) => (
                  <tr key={row.id} className="hover:bg-gray-50/50">
                    <td className="whitespace-nowrap px-6 py-3 text-sm text-gray-700">
                      {row.target_kind === 'console'
                        ? t('access.targetConsole')
                        : t('access.targetApp')}
                      {row.app_id && (
                        <span className="ml-1 text-gray-400">({row.app_id})</span>
                      )}
                    </td>
                    <td className="px-6 py-3 text-sm text-gray-600">{row.role_id}</td>
                    <td className="px-6 py-3 text-sm text-gray-600">
                      {row.requester_subject_type}:{row.requester_subject_id || '—'}
                    </td>
                    <td className="px-6 py-3 text-sm text-gray-600">
                      {row.approver_subject_type}:{row.approver_subject_id || '—'}
                    </td>
                    <td className="whitespace-nowrap px-6 py-3 text-sm text-gray-600">
                      {row.allowed_durations
                        .map((d) => DURATION_LABELS[d] ?? `${d}s`)
                        .join(' / ')}
                    </td>
                    <td className="px-6 py-3 text-right">
                      <Button
                        size="sm"
                        variant="danger"
                        onClick={() => void remove(row.id)}
                      >
                        {t('common.delete')}
                      </Button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </motion.div>
  )
}
