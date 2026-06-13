import { client, systemClient } from './client'
import type { ApiResponse } from '../types'

// SystemInfo mirrors bootstrap.SystemInfo on the Go side.
// All URLs are absolute and operator-configured. Frontends MUST use these
// verbatim instead of guessing from window.location (which breaks behind
// reverse proxies and under custom-path deployments like /admin).
export interface SystemInfo {
  issuer_url: string
  portal_url: string
  console_url: string
  version?: string
}

// BuildInfo / VersionStatus mirror pkg/updatecheck on the Go side.
export interface BuildInfo {
  version: string
  commit: string
  build_time: string
}

export interface ReleaseInfo {
  version: string
  name?: string
  url?: string
  published_at?: string
}

export interface VersionStatus {
  current: BuildInfo
  latest?: ReleaseInfo
  update_available: boolean
  checked_at?: string
  error?: string
}

export const systemApi = {
  info: () =>
    systemClient.get<ApiResponse<SystemInfo>>('/info').then(r => r.data.data),

  // Cached version status (super_admin). Safe to call on page load.
  versionStatus: () =>
    client.get<ApiResponse<VersionStatus>>('/system/version').then(r => r.data.data),

  // Force a live re-check against the release source (the "check now" button).
  checkUpdate: () =>
    client.post<ApiResponse<VersionStatus>>('/system/version/check').then(r => r.data.data),
}
