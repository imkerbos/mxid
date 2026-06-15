// AppGroupRolesAggregated — read-only summary of every member app's
// role catalog + bindings inside an app-group. Sits BELOW the group-level
// catalog so admins see the full picture: what the group inherits + what
// each app additionally defines on its own.
//
// Use case: admin opens the app-group's role tab → sees:
//   1. Group-level catalog (editable, cascades to all member apps)
//   2. Per-member-app catalog (read-only summary; click to navigate to
//      the app's own roles tab for edits)
import { useCallback, useEffect, useState } from 'react'
import { Loader2, Shield, AppWindow, ChevronRight } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { appRoleApi, useTranslation } from '@mxid/shared'
import type { MemberAppRoles } from '@mxid/shared'
import { Tag } from '../../components/ui'
import { toast } from '../../components/ui/toast'

export default function AppGroupRolesAggregated({ groupId }: { groupId: string }) {
  const { t } = useTranslation()
  const [list, setList] = useState<MemberAppRoles[]>([])
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const rows = await appRoleApi.listMemberAppsRoles(groupId)
      setList(rows)
    } catch {
      toast.error(t('apps.aggregated.loadFailed'))
    } finally {
      setLoading(false)
    }
  }, [groupId, t])

  useEffect(() => { load() }, [load])

  if (loading) return <Loader2 className="mx-auto my-8 h-5 w-5 animate-spin text-gray-400" />
  if (list.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-gray-200 py-6 text-center text-sm text-gray-400">
        {t('apps.aggregated.emptyMembers')}
      </div>
    )
  }

  const openApp = (appId: string) => {
    navigate(`/apps?app=${appId}&tab=apps&detail_tab=roles`)
  }

  return (
    <div className="space-y-3">
      {list.map((m) => (
        <div key={m.app_id} className="rounded-xl border border-gray-200 bg-white">
          <button
            type="button"
            onClick={() => openApp(m.app_id)}
            className="flex w-full items-center justify-between gap-3 border-b border-gray-100 px-4 py-3 transition-colors hover:bg-gray-50"
          >
            <div className="flex min-w-0 items-center gap-2.5">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                <AppWindow className="h-4 w-4 text-primary" />
              </div>
              <div className="min-w-0 text-left">
                <div className="truncate text-sm font-semibold text-gray-900">{m.app_name}</div>
                <div className="truncate font-mono text-xs text-gray-400">{m.app_code}</div>
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <Tag>{t('apps.aggregated.rolesCount', { count: m.roles.length })}</Tag>
              <Tag variant="primary">{t('apps.aggregated.bindingsCount', { count: m.bindings.length })}</Tag>
              <ChevronRight className="h-4 w-4 text-gray-300" />
            </div>
          </button>

          <div className="space-y-3 px-4 py-3">
            {/* Roles */}
            <div>
              <div className="mb-1.5 text-xs font-medium text-gray-500">{t('apps.aggregated.rolesCatalog')}</div>
              {m.roles.length === 0 ? (
                <p className="text-xs text-gray-400">{t('apps.aggregated.undefined')}</p>
              ) : (
                <div className="flex flex-wrap gap-1.5">
                  {m.roles.map((r) => (
                    <span
                      key={r.id}
                      className="inline-flex items-center gap-1 rounded-md bg-primary/5 px-2 py-0.5 text-xs text-primary"
                    >
                      <Shield className="h-3 w-3" />
                      {r.name}
                      <span className="font-mono text-primary/60">({r.code})</span>
                      {r.is_default && <span className="ml-0.5 text-amber-500" title={t('apps.aggregated.defaultMark')}>★</span>}
                    </span>
                  ))}
                </div>
              )}
            </div>

            {/* Bindings */}
            <div>
              <div className="mb-1.5 text-xs font-medium text-gray-500">{t('apps.aggregated.bindings')}</div>
              {m.bindings.length === 0 ? (
                <p className="text-xs text-gray-400">{t('apps.aggregated.noBindings')}</p>
              ) : (
                <div className="space-y-1">
                  {m.bindings.map((b) => (
                    <div key={b.id} className="flex items-center gap-2 text-xs">
                      <span className="text-gray-500">{subjectLabel(b.subject_type, t)}</span>
                      <span className="text-gray-700">{b.subject_name || t('apps.aggregated.unknown')}</span>
                      <span className="text-gray-300">→</span>
                      <span className="font-medium text-primary">{b.role_name}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}

function subjectLabel(type: string, t: (k: string) => string): string {
  switch (type) {
    case 'user': return t('apps.aggregated.subjectLabels.user')
    case 'group': return t('apps.aggregated.subjectLabels.group')
    case 'org': return t('apps.aggregated.subjectLabels.org')
    case 'role': return t('apps.aggregated.subjectLabels.role')
    default: return type
  }
}
