import axios, { type AxiosInstance, type AxiosResponse } from 'axios'
import JSONbig from 'json-bigint'
import type { ApiResponse } from '../types'

// Server-issued IDs are snowflake int64 — they exceed JS Number.MAX_SAFE_INTEGER
// (2^53). axios' default JSON.parse silently rounds the last few digits, which
// breaks FK lookups (the rounded id no longer matches the DB row).
//
// json-bigint with storeAsString=true serialises every integer past the safe
// range as a string. Smaller integers (page counts, statuses, etc.) stay as
// numbers so existing code keeps compiling. Backend dtos that tag ID fields
// with `json:"id,string"` already return strings — that path is also safe.
const bigIntParser = JSONbig({ storeAsString: true })

function parseLargeIntsSafe(data: unknown): unknown {
  if (typeof data !== 'string') return data
  try {
    return bigIntParser.parse(data)
  } catch {
    return data
  }
}

// Local-storage key for the console-selected tenant id. The request
// interceptor below stamps it onto every request as X-Tenant-ID so the
// backend tenant middleware can route the request through the right tenant.
// Backend gates the override behind `tenant.manage` (super_admin), so a
// regular tenant admin can't escape their own tenant even if they tinker
// with localStorage.
export const ACTIVE_TENANT_KEY = 'mxid.active_tenant_id'

export function getActiveTenantID(): string | null {
  try {
    return localStorage.getItem(ACTIVE_TENANT_KEY)
  } catch {
    return null
  }
}
export function setActiveTenantID(id: string | null) {
  try {
    if (id) localStorage.setItem(ACTIVE_TENANT_KEY, id)
    else localStorage.removeItem(ACTIVE_TENANT_KEY)
  } catch {
    // ignore
  }
}

export function createApiClient(baseURL: string): AxiosInstance {
  const instance = axios.create({
    baseURL,
    timeout: 15000,
    withCredentials: true,
    headers: {
      'Content-Type': 'application/json',
    },
    transformResponse: [parseLargeIntsSafe],
  })

  instance.interceptors.request.use((config) => {
    const tid = getActiveTenantID()
    if (tid) {
      config.headers = config.headers ?? {}
      ;(config.headers as Record<string, string>)['X-Tenant-ID'] = tid
    }
    return config
  })

  instance.interceptors.response.use(
    (response: AxiosResponse<ApiResponse>) => {
      const data = response.data
      if (data.code !== 0) {
        return Promise.reject(new ApiError(data.code, data.message, data.detail))
      }
      return response
    },
    (error) => {
      if (error.response?.status === 401) {
        window.dispatchEvent(new CustomEvent('mxid:unauthorized'))
      }
      return Promise.reject(error)
    },
  )

  return instance
}

export class ApiError extends Error {
  code: number
  detail?: string

  constructor(code: number, message: string, detail?: string) {
    super(message)
    this.name = 'ApiError'
    this.code = code
    this.detail = detail
  }
}

// Default client for console (/api/v1/console)
export const client = createApiClient('/api/v1/console')

// Portal client (/api/v1/portal)
export const portalClient = createApiClient('/api/v1/portal')

// System client (/api/v1/system) — public unauthenticated metadata. Used by
// both console and portal SPAs to learn the canonical issuer / portal URLs
// before any login or interceptors run.
export const systemClient = createApiClient('/api/v1/system')
