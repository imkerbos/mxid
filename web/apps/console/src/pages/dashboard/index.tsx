import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { Users, AppWindow, LogIn, Radio } from 'lucide-react'
import { auditApi, formatDate, useTranslation } from '@mxid/shared'
import type { AuditLog } from '@mxid/shared'
import PageHeader from '../../components/layout/PageHeader'

interface DashboardStats {
  total_events: number
  login_count: number
  failed_login_count: number
  active_users: number
}

const statCards = [
  { key: 'total_events' as const, labelKey: 'dashboard.stats.totalEvents', icon: Users, color: 'bg-blue-500' },
  { key: 'login_count' as const, labelKey: 'dashboard.stats.loginCount', icon: LogIn, color: 'bg-emerald-500' },
  { key: 'failed_login_count' as const, labelKey: 'dashboard.stats.failedLoginCount', icon: AppWindow, color: 'bg-amber-500' },
  { key: 'active_users' as const, labelKey: 'dashboard.stats.activeUsers', icon: Radio, color: 'bg-violet-500' },
]

export default function DashboardPage() {
  const { t } = useTranslation()
  const [stats, setStats] = useState<DashboardStats>({
    total_events: 0,
    login_count: 0,
    failed_login_count: 0,
    active_users: 0,
  })
  const [recentLogs, setRecentLogs] = useState<AuditLog[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const load = async () => {
      try {
        const [statsData, logsData] = await Promise.all([
          auditApi.stats(),
          auditApi.list({ page: 1, page_size: 10 }),
        ])
        setStats(statsData as unknown as DashboardStats)
        setRecentLogs(logsData.items)
      } catch {
        // silently fail, show empty state
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [])

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.3 }}>
      <PageHeader title={t('dashboard.title')} description={t('dashboard.description')} />

      {/* Stat cards */}
      <div className="mb-8 grid grid-cols-1 gap-5 sm:grid-cols-2 xl:grid-cols-4">
        {statCards.map((card, i) => (
          <motion.div
            key={card.key}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.08, duration: 0.3 }}
            className="rounded-xl border border-gray-100 bg-white p-5 shadow-sm"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-500">{t(card.labelKey)}</p>
                <p className="mt-1 text-3xl font-bold text-gray-900">
                  {loading ? '-' : (stats[card.key] ?? 0).toLocaleString()}
                </p>
              </div>
              <div className={`flex h-12 w-12 items-center justify-center rounded-xl ${card.color} text-white`}>
                <card.icon className="h-6 w-6" />
              </div>
            </div>
          </motion.div>
        ))}
      </div>

      {/* Recent audit logs */}
      <div className="rounded-xl border border-gray-100 bg-white shadow-sm">
        <div className="border-b border-gray-100 px-6 py-4">
          <h2 className="text-lg font-semibold text-gray-900">{t('dashboard.recentAudit')}</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-50 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                <th className="px-6 py-3">{t('dashboard.cols.time')}</th>
                <th className="px-6 py-3">{t('dashboard.cols.eventType')}</th>
                <th className="px-6 py-3">{t('dashboard.cols.actor')}</th>
                <th className="px-6 py-3">{t('dashboard.cols.resourceType')}</th>
                <th className="px-6 py-3">{t('dashboard.cols.ip')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {loading ? (
                <tr>
                  <td colSpan={5} className="px-6 py-10 text-center text-sm text-gray-400">
                    {t('common.loading')}
                  </td>
                </tr>
              ) : recentLogs.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-6 py-10 text-center text-sm text-gray-400">
                    {t('common.empty')}
                  </td>
                </tr>
              ) : (
                recentLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-gray-50/50">
                    <td className="whitespace-nowrap px-6 py-3 text-sm text-gray-600">
                      {formatDate(log.created_at)}
                    </td>
                    <td className="px-6 py-3">
                      <span className="inline-flex rounded-full bg-blue-50 px-2.5 py-0.5 text-xs font-medium text-blue-700">
                        {log.event_type}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-sm text-gray-600">
                      {log.actor_name || '-'}
                    </td>
                    <td className="px-6 py-3 text-sm text-gray-600">{log.resource_type}</td>
                    <td className="px-6 py-3 text-sm text-gray-400">{log.ip || '-'}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </motion.div>
  )
}
