import { systemClient } from './client'
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

export const systemApi = {
  info: () =>
    systemClient.get<ApiResponse<SystemInfo>>('/info').then(r => r.data.data),
}
