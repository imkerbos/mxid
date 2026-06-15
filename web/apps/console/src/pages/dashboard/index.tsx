import { useEffect, useMemo, useState } from 'react'
import { motion } from 'framer-motion'
import {
  Users, AppWindow, LogIn, Radio, ShieldAlert, KeyRound, UserPlus, Percent, Download,
} from 'lucide-react'
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  PieChart, Pie, Cell, BarChart, Bar,
} from 'recharts'
import { auditApi, dashboardApi, formatDate, useTranslation } from '@mxid/shared'
import { pageMotion } from '@mxid/shared/ui'
import type { AuditLog, DashboardOverview } from '@mxid/shared'
import PageHeader from '../../components/layout/PageHeader'

// Chart palette — kept local so the dashboard owns its look without leaking a
// global theme dependency. Greens/reds carry success/failure semantics; the
// categorical ring is for protocol / method / geo slices.
const C = {
  success: '#10b981',
  failed: '#ef4444',
  cat: ['#6366f1', '#06b6d4', '#f59e0b', '#10b981', '#ec4899', '#8b5cf6', '#84cc16', '#f43f5e'],
}

const pct = (n: number) => `${(n * 100).toFixed(1)}%`

export default function DashboardPage() {
  const { t } = useTranslation()
  const [range, setRange] = useState(7)
  const [data, setData] = useState<DashboardOverview | null>(null)
  const [recentLogs, setRecentLogs] = useState<AuditLog[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let alive = true
    setLoading(true)
    Promise.all([
      dashboardApi.overview({ range }),
      auditApi.list({ page: 1, page_size: 8 }),
    ])
      .then(([ov, logs]) => {
        if (!alive) return
        setData(ov)
        setRecentLogs(logs.items)
      })
      .catch(() => {})
      .finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
  }, [range])

  const kpis = useMemo(() => {
    if (!data) return []
    const c = data.counts
    const a = data.auth
    return [
      { key: 'users', icon: Users, color: 'bg-blue-500', value: c.users.toLocaleString(),
        label: t('dashboard.kpi.users'), sub: t('dashboard.kpi.usersActive', { n: c.users_active }) },
      { key: 'apps', icon: AppWindow, color: 'bg-indigo-500', value: c.apps.toLocaleString(),
        label: t('dashboard.kpi.apps') },
      { key: 'dau', icon: Radio, color: 'bg-violet-500', value: a.dau.toLocaleString(),
        label: t('dashboard.kpi.dau'),
        sub: `${t('dashboard.windows.wau')} ${a.wau} · ${t('dashboard.windows.mau')} ${a.mau}` },
      { key: 'logins', icon: LogIn, color: 'bg-emerald-500', value: a.today_logins.toLocaleString(),
        label: t('dashboard.kpi.todayLogins') },
      { key: 'rate', icon: Percent, color: 'bg-teal-500', value: pct(a.success_rate),
        label: t('dashboard.kpi.successRate') },
      { key: 'mfa', icon: KeyRound, color: 'bg-cyan-600', value: pct(c.mfa_coverage),
        label: t('dashboard.kpi.mfaCoverage') },
      { key: 'new', icon: UserPlus, color: 'bg-amber-500', value: c.new_users.toLocaleString(),
        label: t('dashboard.kpi.newUsers') },
      { key: 'risk', icon: ShieldAlert, color: data.security.risk_events > 0 ? 'bg-red-500' : 'bg-gray-400',
        value: data.security.risk_events.toLocaleString(), label: t('dashboard.kpi.riskEvents') },
    ]
  }, [data, t])

  const sec = data?.security

  return (
    <motion.div {...pageMotion}>
      <div className="flex flex-wrap items-end justify-between gap-3">
        <PageHeader title={t('dashboard.title')} description={t('dashboard.description')} />
        <div className="mb-1 flex items-center gap-2">
          <div className="flex rounded-lg border border-gray-200 bg-white p-0.5 text-sm">
            {[7, 30].map((d) => (
              <button
                key={d}
                onClick={() => setRange(d)}
                className={`rounded-md px-3 py-1.5 font-medium transition ${
                  range === d ? 'bg-blue-600 text-white' : 'text-gray-600 hover:bg-gray-50'
                }`}
              >
                {t(d === 7 ? 'dashboard.range.d7' : 'dashboard.range.d30')}
              </button>
            ))}
          </div>
          <a
            href={dashboardApi.exportHref(range)}
            className="inline-flex items-center gap-1.5 rounded-lg border border-gray-200 bg-white px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50"
          >
            <Download className="h-4 w-4" /> {t('dashboard.export')}
          </a>
        </div>
      </div>

      {/* KPI cards */}
      <div className="mb-6 mt-4 grid grid-cols-2 gap-4 lg:grid-cols-4 xl:grid-cols-8">
        {loading
          ? Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="rounded-xl border border-gray-100 bg-white p-4 shadow-sm">
                <p className="text-xs text-gray-500">—</p>
                <p className="mt-2 text-2xl font-bold text-gray-900">-</p>
              </div>
            ))
          : kpis.map((card, i) => (
              <motion.div
                key={card.key}
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.04, duration: 0.25 }}
                className="rounded-xl border border-gray-100 bg-white p-4 shadow-sm"
              >
                <div className="flex items-center justify-between">
                  <p className="text-xs text-gray-500">{card.label}</p>
                  <div className={`flex h-8 w-8 items-center justify-center rounded-lg ${card.color} text-white`}>
                    <card.icon className="h-4 w-4" />
                  </div>
                </div>
                <p className="mt-2 text-2xl font-bold text-gray-900">{card.value}</p>
                {card.sub && <p className="mt-0.5 text-xs text-gray-400">{card.sub}</p>}
              </motion.div>
            ))}
      </div>

      {/* Row: login trend + auth methods */}
      <div className="mb-6 grid grid-cols-1 gap-5 lg:grid-cols-3">
        <Card title={t('dashboard.charts.loginTrend')} className="lg:col-span-2">
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={data?.login_trend ?? []} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
              <defs>
                <linearGradient id="gS" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={C.success} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={C.success} stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gF" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={C.failed} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={C.failed} stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
              <XAxis dataKey="date" tick={{ fontSize: 11, fill: '#94a3b8' }} tickFormatter={(d: string) => d.slice(5)} />
              <YAxis tick={{ fontSize: 11, fill: '#94a3b8' }} allowDecimals={false} />
              <Tooltip />
              <Legend iconType="circle" wrapperStyle={{ fontSize: 12 }} />
              <Area type="monotone" dataKey="success" name={t('dashboard.charts.success')}
                stroke={C.success} fill="url(#gS)" strokeWidth={2} />
              <Area type="monotone" dataKey="failed" name={t('dashboard.charts.failed')}
                stroke={C.failed} fill="url(#gF)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </Card>

        <Card title={t('dashboard.charts.authMethods')}>
          <DonutChart data={data?.auth_methods ?? []} empty={t('dashboard.charts.noData')} />
        </Card>
      </div>

      {/* Row: top apps + geo + protocol */}
      <div className="mb-6 grid grid-cols-1 gap-5 lg:grid-cols-3">
        <Card title={t('dashboard.charts.topApps')}>
          <HBar data={data?.top_apps ?? []} color={C.cat[0]} empty={t('dashboard.charts.noData')} />
        </Card>
        <Card title={t('dashboard.charts.geoTop')}>
          <HBar data={data?.geo_top ?? []} color={C.cat[1]} empty={t('dashboard.charts.noData')} />
        </Card>
        <Card title={t('dashboard.charts.appsByProtocol')}>
          <DonutChart data={data?.counts.apps_by_protocol ?? []} empty={t('dashboard.charts.noData')} />
        </Card>
      </div>

      {/* Row: security feed + recent audit */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <Card title={t('dashboard.security.title')}>
          <div className="mb-3 grid grid-cols-5 gap-2 text-center">
            {[
              { l: t('dashboard.security.riskEvents'), v: sec?.risk_events },
              { l: t('dashboard.security.lockedUsers'), v: sec?.locked_users },
              { l: t('dashboard.security.tokenReuse'), v: sec?.token_reuse },
              { l: t('dashboard.security.superAdminGrants'), v: sec?.super_admin_grants },
              { l: t('dashboard.security.piiViews'), v: sec?.pii_views },
            ].map((s, i) => (
              <div key={i} className="rounded-lg bg-gray-50 px-1 py-2">
                <p className="text-lg font-bold text-gray-900">{s.v ?? 0}</p>
                <p className="mt-0.5 text-[10px] leading-tight text-gray-500">{s.l}</p>
              </div>
            ))}
          </div>
          <div className="divide-y divide-gray-50">
            {(sec?.recent ?? []).length === 0 ? (
              <p className="py-8 text-center text-sm text-gray-400">{t('dashboard.security.empty')}</p>
            ) : (
              sec!.recent.map((e, i) => (
                <div key={i} className="flex items-center justify-between py-2 text-sm">
                  <span className="inline-flex rounded-full bg-red-50 px-2 py-0.5 text-xs font-medium text-red-600">
                    {e.event_type}
                  </span>
                  <span className="text-gray-600">{e.actor || '-'}</span>
                  <span className="text-xs text-gray-400">{formatDate(e.time)}</span>
                </div>
              ))
            )}
          </div>
        </Card>

        <Card title={t('dashboard.recentAudit')} bodyClass="p-0">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-50 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                  <th className="px-5 py-3">{t('dashboard.cols.time')}</th>
                  <th className="px-5 py-3">{t('dashboard.cols.eventType')}</th>
                  <th className="px-5 py-3">{t('dashboard.cols.actor')}</th>
                  <th className="px-5 py-3">{t('dashboard.cols.ip')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {recentLogs.length === 0 ? (
                  <tr><td colSpan={4} className="px-5 py-10 text-center text-sm text-gray-400">{t('common.empty')}</td></tr>
                ) : (
                  recentLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-gray-50/50">
                      <td className="whitespace-nowrap px-5 py-2.5 text-sm text-gray-600">{formatDate(log.created_at)}</td>
                      <td className="px-5 py-2.5">
                        <span className="inline-flex rounded-full bg-blue-50 px-2 py-0.5 text-xs font-medium text-blue-700">
                          {log.event_type}
                        </span>
                      </td>
                      <td className="px-5 py-2.5 text-sm text-gray-600">{log.actor_name || '-'}</td>
                      <td className="px-5 py-2.5 text-sm text-gray-400">{log.ip || '-'}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </Card>
      </div>

      {data && (
        <p className="mt-4 text-right text-xs text-gray-400">
          {t('dashboard.generatedAt')} {formatDate(data.generated_at)}
        </p>
      )}
    </motion.div>
  )
}

function Card({ title, children, className = '', bodyClass = 'p-5' }: {
  title: string; children: React.ReactNode; className?: string; bodyClass?: string
}) {
  return (
    <div className={`rounded-xl border border-gray-100 bg-white shadow-sm ${className}`}>
      <div className="border-b border-gray-100 px-5 py-3">
        <h2 className="text-sm font-semibold text-gray-900">{title}</h2>
      </div>
      <div className={bodyClass}>{children}</div>
    </div>
  )
}

function DonutChart({ data, empty }: { data: { name: string; value: number }[]; empty: string }) {
  if (!data.length) return <Empty text={empty} />
  return (
    <ResponsiveContainer width="100%" height={240}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={2}>
          {data.map((_, i) => <Cell key={i} fill={C.cat[i % C.cat.length]} />)}
        </Pie>
        <Tooltip />
        <Legend iconType="circle" wrapperStyle={{ fontSize: 12 }} />
      </PieChart>
    </ResponsiveContainer>
  )
}

function HBar({ data, color, empty }: { data: { name: string; value: number }[]; color: string; empty: string }) {
  if (!data.length) return <Empty text={empty} />
  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 16, left: 8, bottom: 4 }}>
        <XAxis type="number" tick={{ fontSize: 11, fill: '#94a3b8' }} allowDecimals={false} />
        <YAxis type="category" dataKey="name" width={90} tick={{ fontSize: 11, fill: '#64748b' }} />
        <Tooltip cursor={{ fill: '#f8fafc' }} />
        <Bar dataKey="value" fill={color} radius={[0, 4, 4, 0]} barSize={16} />
      </BarChart>
    </ResponsiveContainer>
  )
}

function Empty({ text }: { text: string }) {
  return <div className="flex h-[240px] items-center justify-center text-sm text-gray-400">{text}</div>
}
