import { useEffect, useMemo, useState } from 'react'
import { motion } from 'framer-motion'
import {
  Users, AppWindow, LogIn, Radio, ShieldAlert, KeyRound, UserPlus, Percent, Download,
} from 'lucide-react'
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  PieChart, Pie, Cell, BarChart, Bar,
} from 'recharts'
import { auditApi, dashboardApi, formatDate, useTranslation, useTheme } from '@mxid/shared'
import { pageMotion, Card, CardHeader, StatCard } from '@mxid/shared/ui'
import type { AuditLog, DashboardOverview } from '@mxid/shared'
import PageHeader from '../../components/layout/PageHeader'

// Categorical ring palette for protocol / method / geo slices (theme-neutral).
const CAT = ['#6366f1', '#06b6d4', '#f59e0b', '#10b981', '#ec4899', '#8b5cf6', '#84cc16', '#f43f5e']
const C_SUCCESS = '#10b981'
const C_FAILED = '#ef4444'

const pct = (n: number) => `${(n * 100).toFixed(1)}%`

// Recharts renders inline SVG colors (not utility classes), so the dark compat
// shim can't reach them — resolve axis/grid/tooltip colors from the theme mode.
function useChartTheme() {
  const dark = useTheme((s) => s.mode) === 'dark'
  return {
    dark,
    axis: dark ? '#64748b' : '#94a3b8',
    axisStrong: dark ? '#94a3b8' : '#64748b',
    grid: dark ? '#1e293b' : '#f1f5f9',
    cursor: dark ? 'rgba(148,163,184,0.08)' : '#f8fafc',
    tooltip: dark
      ? { background: '#131927', border: '1px solid #2a3448', borderRadius: 8, color: '#e2e8f0' }
      : { borderRadius: 8 },
  }
}

type KpiTone = 'default' | 'primary' | 'success' | 'warning' | 'danger' | 'info'

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
      { key: 'users', icon: Users, tone: 'default' as KpiTone, value: c.users.toLocaleString(),
        label: t('dashboard.kpi.users'), sub: t('dashboard.kpi.usersActive', { n: c.users_active }) },
      { key: 'apps', icon: AppWindow, tone: 'primary' as KpiTone, value: c.apps.toLocaleString(),
        label: t('dashboard.kpi.apps') },
      { key: 'dau', icon: Radio, tone: 'info' as KpiTone, value: a.dau.toLocaleString(),
        label: t('dashboard.kpi.dau'),
        sub: `${t('dashboard.windows.wau')} ${a.wau} · ${t('dashboard.windows.mau')} ${a.mau}` },
      { key: 'logins', icon: LogIn, tone: 'success' as KpiTone, value: a.today_logins.toLocaleString(),
        label: t('dashboard.kpi.todayLogins') },
      { key: 'rate', icon: Percent, tone: 'success' as KpiTone, value: pct(a.success_rate),
        label: t('dashboard.kpi.successRate') },
      { key: 'mfa', icon: KeyRound, tone: 'info' as KpiTone, value: pct(c.mfa_coverage),
        label: t('dashboard.kpi.mfaCoverage') },
      { key: 'new', icon: UserPlus, tone: 'warning' as KpiTone, value: c.new_users.toLocaleString(),
        label: t('dashboard.kpi.newUsers') },
      { key: 'risk', icon: ShieldAlert, tone: (data.security.risk_events > 0 ? 'danger' : 'default') as KpiTone,
        value: data.security.risk_events.toLocaleString(), label: t('dashboard.kpi.riskEvents') },
    ]
  }, [data, t])

  const sec = data?.security

  return (
    <motion.div {...pageMotion}>
      <div className="flex flex-wrap items-end justify-between gap-3">
        <PageHeader title={t('dashboard.title')} description={t('dashboard.description')} />
        <div className="mb-1 flex items-center gap-2">
          <div className="flex rounded-lg border border-border bg-surface p-0.5 text-sm">
            {[7, 30].map((d) => (
              <button
                key={d}
                onClick={() => setRange(d)}
                className={`rounded-md px-3 py-1.5 font-medium transition ${
                  range === d ? 'bg-primary text-white' : 'text-muted hover:bg-surface-muted'
                }`}
              >
                {t(d === 7 ? 'dashboard.range.d7' : 'dashboard.range.d30')}
              </button>
            ))}
          </div>
          <a
            href={dashboardApi.exportHref(range)}
            className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-surface px-3 py-1.5 text-sm font-medium text-ink hover:bg-surface-muted"
          >
            <Download className="h-4 w-4" /> {t('dashboard.export')}
          </a>
        </div>
      </div>

      {/* KPI cards */}
      <div className="mb-6 mt-4 grid grid-cols-2 gap-4 lg:grid-cols-4">
        {loading
          ? Array.from({ length: 8 }).map((_, i) => (
              <Card key={i} className="p-4">
                <p className="text-xs text-muted">—</p>
                <p className="mt-2 text-2xl font-bold text-ink">-</p>
              </Card>
            ))
          : kpis.map((card, i) => (
              <motion.div
                key={card.key}
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.04, duration: 0.25 }}
              >
                <StatCard label={card.label} value={card.value} icon={card.icon} tone={card.tone} sub={card.sub} />
              </motion.div>
            ))}
      </div>

      {/* Row: login trend + auth methods */}
      <div className="mb-6 grid grid-cols-1 gap-5 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <ChartPanel title={t('dashboard.charts.loginTrend')}>
            <LoginTrendChart data={data?.login_trend ?? []} labels={{ success: t('dashboard.charts.success'), failed: t('dashboard.charts.failed') }} />
          </ChartPanel>
        </div>
        <ChartPanel title={t('dashboard.charts.authMethods')}>
          <DonutChart data={data?.auth_methods ?? []} empty={t('dashboard.charts.noData')} />
        </ChartPanel>
      </div>

      {/* Row: top apps + geo + protocol */}
      <div className="mb-6 grid grid-cols-1 gap-5 lg:grid-cols-3">
        <ChartPanel title={t('dashboard.charts.topApps')}>
          <HBar data={data?.top_apps ?? []} color={CAT[0]} empty={t('dashboard.charts.noData')} />
        </ChartPanel>
        <ChartPanel title={t('dashboard.charts.geoTop')}>
          <HBar data={data?.geo_top ?? []} color={CAT[1]} empty={t('dashboard.charts.noData')} />
        </ChartPanel>
        <ChartPanel title={t('dashboard.charts.appsByProtocol')}>
          <DonutChart data={data?.counts.apps_by_protocol ?? []} empty={t('dashboard.charts.noData')} />
        </ChartPanel>
      </div>

      {/* Row: security feed + recent audit */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <Card className="hover:shadow-card">
          <CardHeader title={t('dashboard.security.title')} />
          <div className="p-5">
            <div className="mb-3 grid grid-cols-5 gap-2 text-center">
              {[
                { l: t('dashboard.security.riskEvents'), v: sec?.risk_events },
                { l: t('dashboard.security.lockedUsers'), v: sec?.locked_users },
                { l: t('dashboard.security.tokenReuse'), v: sec?.token_reuse },
                { l: t('dashboard.security.superAdminGrants'), v: sec?.super_admin_grants },
                { l: t('dashboard.security.piiViews'), v: sec?.pii_views },
              ].map((s, i) => (
                <div key={i} className="rounded-lg bg-surface-muted px-1 py-2">
                  <p className="text-lg font-bold text-ink">{s.v ?? 0}</p>
                  <p className="mt-0.5 text-[10px] leading-tight text-muted">{s.l}</p>
                </div>
              ))}
            </div>
            <div className="divide-y divide-border">
              {(sec?.recent ?? []).length === 0 ? (
                <p className="py-8 text-center text-sm text-faint">{t('dashboard.security.empty')}</p>
              ) : (
                sec!.recent.map((e, i) => (
                  <div key={i} className="flex items-center justify-between py-2 text-sm">
                    <span className="inline-flex rounded-full bg-danger/10 px-2 py-0.5 text-xs font-medium text-danger">
                      {e.event_type}
                    </span>
                    <span className="text-muted">{e.actor || '-'}</span>
                    <span className="text-xs text-faint">{formatDate(e.time)}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </Card>

        <Card className="overflow-hidden hover:shadow-card">
          <CardHeader title={t('dashboard.recentAudit')} />
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border bg-surface-muted text-left text-xs font-medium uppercase tracking-wider text-faint">
                  <th className="px-5 py-3">{t('dashboard.cols.time')}</th>
                  <th className="px-5 py-3">{t('dashboard.cols.eventType')}</th>
                  <th className="px-5 py-3">{t('dashboard.cols.actor')}</th>
                  <th className="px-5 py-3">{t('dashboard.cols.ip')}</th>
                </tr>
              </thead>
              <tbody>
                {recentLogs.length === 0 ? (
                  <tr><td colSpan={4} className="px-5 py-10 text-center text-sm text-faint">{t('common.empty')}</td></tr>
                ) : (
                  recentLogs.map((log) => (
                    <tr key={log.id} className="border-b border-border/60 transition-colors last:border-0 hover:bg-surface-muted">
                      <td className="whitespace-nowrap px-5 py-2.5 text-sm text-muted">{formatDate(log.created_at)}</td>
                      <td className="px-5 py-2.5">
                        <span className="inline-flex rounded-full bg-info/10 px-2 py-0.5 text-xs font-medium text-info">
                          {log.event_type}
                        </span>
                      </td>
                      <td className="px-5 py-2.5 text-sm text-muted">{log.actor_name || '-'}</td>
                      <td className="px-5 py-2.5 text-sm text-faint">{log.ip || '-'}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </Card>
      </div>

      {data && (
        <p className="mt-4 text-right text-xs text-faint">
          {t('dashboard.generatedAt')} {formatDate(data.generated_at)}
        </p>
      )}
    </motion.div>
  )
}

function ChartPanel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Card className="hover:shadow-card">
      <CardHeader title={title} />
      <div className="p-3">{children}</div>
    </Card>
  )
}

function LoginTrendChart({ data, labels }: { data: unknown[]; labels: { success: string; failed: string } }) {
  const ct = useChartTheme()
  return (
    <ResponsiveContainer width="100%" height={260}>
      <AreaChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
        <defs>
          <linearGradient id="gS" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor={C_SUCCESS} stopOpacity={0.3} />
            <stop offset="95%" stopColor={C_SUCCESS} stopOpacity={0} />
          </linearGradient>
          <linearGradient id="gF" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor={C_FAILED} stopOpacity={0.3} />
            <stop offset="95%" stopColor={C_FAILED} stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke={ct.grid} />
        <XAxis dataKey="date" tick={{ fontSize: 11, fill: ct.axis }} tickFormatter={(d: string) => d.slice(5)} />
        <YAxis tick={{ fontSize: 11, fill: ct.axis }} allowDecimals={false} />
        <Tooltip contentStyle={ct.tooltip} labelStyle={{ color: ct.tooltip.color }} />
        <Legend iconType="circle" wrapperStyle={{ fontSize: 12 }} />
        <Area type="monotone" dataKey="success" name={labels.success} stroke={C_SUCCESS} fill="url(#gS)" strokeWidth={2} />
        <Area type="monotone" dataKey="failed" name={labels.failed} stroke={C_FAILED} fill="url(#gF)" strokeWidth={2} />
      </AreaChart>
    </ResponsiveContainer>
  )
}

function DonutChart({ data, empty }: { data: { name: string; value: number }[]; empty: string }) {
  const ct = useChartTheme()
  if (!data.length) return <Empty text={empty} />
  return (
    <ResponsiveContainer width="100%" height={240}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={2}>
          {data.map((_, i) => <Cell key={i} fill={CAT[i % CAT.length]} />)}
        </Pie>
        <Tooltip contentStyle={ct.tooltip} labelStyle={{ color: ct.tooltip.color }} />
        <Legend iconType="circle" wrapperStyle={{ fontSize: 12 }} />
      </PieChart>
    </ResponsiveContainer>
  )
}

function HBar({ data, color, empty }: { data: { name: string; value: number }[]; color: string; empty: string }) {
  const ct = useChartTheme()
  if (!data.length) return <Empty text={empty} />
  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 16, left: 8, bottom: 4 }}>
        <XAxis type="number" tick={{ fontSize: 11, fill: ct.axis }} allowDecimals={false} />
        <YAxis type="category" dataKey="name" width={90} tick={{ fontSize: 11, fill: ct.axisStrong }} />
        <Tooltip cursor={{ fill: ct.cursor }} contentStyle={ct.tooltip} labelStyle={{ color: ct.tooltip.color }} />
        <Bar dataKey="value" fill={color} radius={[0, 4, 4, 0]} barSize={16} />
      </BarChart>
    </ResponsiveContainer>
  )
}

function Empty({ text }: { text: string }) {
  return <div className="flex h-[240px] items-center justify-center text-sm text-faint">{text}</div>
}
