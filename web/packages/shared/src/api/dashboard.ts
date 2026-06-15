import { client } from './client'
import type { ApiResponse } from '../types'

export interface NameValue {
  name: string
  value: number
}

export interface TrendPoint {
  date: string
  success: number
  failed: number
}

export interface SecurityEvent {
  time: string
  event_type: string
  actor: string
  ip: string
}

export interface DashboardOverview {
  counts: {
    users: number
    users_active: number
    apps: number
    apps_by_protocol: NameValue[]
    orgs: number
    groups: number
    identity_sources: number
    active_sessions: number
    mfa_enrolled: number
    mfa_coverage: number
    new_users: number
  }
  auth: {
    today_logins: number
    login_success: number
    login_failed: number
    success_rate: number
    dau: number
    wau: number
    mau: number
  }
  login_trend: TrendPoint[]
  auth_methods: NameValue[]
  top_apps: NameValue[]
  geo_top: NameValue[]
  security: {
    risk_events: number
    locked_users: number
    token_reuse: number
    super_admin_grants: number
    pii_views: number
    recent: SecurityEvent[]
  }
  range_days: number
  generated_at: string
}

export const dashboardApi = {
  overview: (params?: { range?: number; tenant_id?: string }) =>
    client
      .get<ApiResponse<DashboardOverview>>('/dashboard/overview', { params })
      .then((r) => r.data.data),
  // Same-origin link; the browser sends the console session cookie. Used as an
  // <a href> so the CSV streams straight to a file download.
  exportHref: (range: number) => `/api/v1/console/dashboard/export?range=${range}`,
}
