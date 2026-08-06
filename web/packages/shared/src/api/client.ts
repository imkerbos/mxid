import axios, { type AxiosInstance, type AxiosResponse } from 'axios'
import JSONbig from 'json-bigint'
import type { ApiResponse } from '../types'

// skipAuthEvent opts a single request out of the global mxid:unauthorized
// dispatch on 401. The SSO-bridge bootstrap uses it: a 401 from the initial
// /auth/me probe or the /auth/sso attempt must NOT trigger the app-wide
// redirect-to-login, or it would race the bridge. The AuthGuard owns the
// fallback in that flow instead.
//
// _stepUpRetried marks a request that has already been replayed once after a
// step-up challenge, so a persistent 40330 can't loop forever.
declare module 'axios' {
  interface AxiosRequestConfig {
    skipAuthEvent?: boolean
    _stepUpRetried?: boolean
  }
}

// Backend response codes the client reacts to globally.
//
// These live here rather than inline at each branch because the numbers are a
// wire contract with pkg/errcode/catalog.go, and a backend renumber has to be
// findable from one place. CAPTCHA_REQUIRED moved from 40003 to 40016 when the
// backend stopped reusing a code the SPA localizes: 40003 renders as "that code
// was just used", so a login that needed a captcha said the wrong thing.
export const CODE_UNAUTHENTICATED = 40101
export const CODE_INVALID_MFA_CODE = 40102
// Step-up refusal on the change-password route: the account has TOTP enrolled
// and no code was supplied. errcode.NumTOTPRequired.
export const CODE_TOTP_REQUIRED = 40007
// A captcha is now DEMANDED (first time, after repeated failures) — distinct
// from one being typed WRONG. The sign-in screen said "incorrect captcha" for
// both, so the first demand accused the user of mistyping a box they had not
// been shown yet.
export const CODE_CAPTCHA_REQUIRED = 40016
export const CODE_CAPTCHA_INVALID = 40004
// Account-state refusals at sign-in. Each needs its own sentence: "locked"
// resolves itself or needs an administrator, "disabled" always needs one, and
// "expired" is the user's own to fix.
export const CODE_ACCESS_DENIED = 40302
export const CODE_ACCOUNT_DISABLED = 40303
export const CODE_ACCOUNT_LOCKED = 40304
export const CODE_TOO_MANY_ATTEMPTS = 42901
export const CODE_STEP_UP_REQUIRED = 40330
export const CODE_MFA_ENROLL_REQUIRED = 40331
export const CODE_EE_FEATURE_REQUIRED = 40332
export const CODE_PASSWORD_CHANGE_REQUIRED = 40333

// Step-up handler: the console registers a callback (a modal) that resolves
// once the user passes an MFA challenge. The 403/step_up_required interceptor
// awaits it, then transparently replays the original high-risk request.
type StepUpHandler = () => Promise<void>
let stepUpHandler: StepUpHandler | null = null
export function setStepUpHandler(fn: StepUpHandler | null) {
  stepUpHandler = fn
}

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
        return Promise.reject(new ApiError(data.code, data.message, data.detail, data.traceId))
      }
      return response
    },
    async (error) => {
      const status = error.response?.status
      const code = error.response?.data?.code

      if (status === 401 && !error.config?.skipAuthEvent) {
        window.dispatchEvent(new CustomEvent('mxid:unauthorized'))
      }

      // High-risk operation needs a fresh MFA. Run the step-up modal, then
      // replay the original request exactly once.
      if (
        status === 403 &&
        code === CODE_STEP_UP_REQUIRED &&
        stepUpHandler &&
        error.config &&
        !error.config._stepUpRetried
      ) {
        try {
          await stepUpHandler()
          error.config._stepUpRetried = true
          return instance(error.config)
        } catch {
          return Promise.reject(error)
        }
      }

      // Policy requires MFA but the user has none enrolled — route them to
      // enrollment; the SPA listens for this and navigates.
      if (status === 403 && code === CODE_MFA_ENROLL_REQUIRED) {
        window.dispatchEvent(new CustomEvent('mxid:mfa-enroll-required'))
      }

      // The account owes a password change — an admin reset it, or it still
      // carries the one it was seeded with. Every other route 403s until it is
      // done, so the SPA renders only the change screen rather than a wall of
      // failed requests.
      if (status === 403 && code === CODE_PASSWORD_CHANGE_REQUIRED) {
        window.dispatchEvent(new CustomEvent('mxid:password-change-required'))
      }

      // Surface the backend's structured error. On any non-2xx HTTP status the
      // server returns {code, message, detail}; without this the SPA only sees
      // axios' generic "Request failed with status code N" and callers reading
      // err.message localize nothing. Fall back to the raw AxiosError when the
      // body is absent (network error, non-JSON gateway page).
      const data = error.response?.data
      if (data && typeof data.code === 'number' && data.code !== 0) {
        return Promise.reject(new ApiError(data.code, data.message, data.detail, data.traceId))
      }

      // No parseable body — a gateway error page, a dropped connection, or a
      // response that never reached the handler. Axios' own message ("Request
      // failed with status code 500") is what the user saw before this, and it
      // says nothing about what to do. Carry the status so the toast can at
      // least name it as a server-side failure.
      if (status) {
        return Promise.reject(new ApiError(-status, `HTTP ${status}`, undefined, undefined))
      }

      return Promise.reject(error)
    },
  )

  return instance
}

// apiErrorCode reads the backend's numeric business code off a rejected
// request, whichever shape it arrives in.
//
// There are two, and mixing them up is silent. The interceptors below reject
// with an ApiError carrying a numeric `.code` and NO `.response`, while a
// failure that never reached them (or a raw axios error) carries the code at
// `response.data.code` and a STRING `.code` such as "ERR_BAD_REQUEST".
//
// Reading only `response.data.code` is what stopped the login captcha from ever
// appearing: the message lookup fell back to `.code` and showed the right text,
// while the branch that reveals the captcha box read the other shape, got
// undefined, and never fired. A user who tripped the captcha threshold could
// not log in at all.
export function apiErrorCode(err: unknown): number | undefined {
  const e = err as { code?: number | string; response?: { data?: { code?: number } } }
  if (typeof e?.code === 'number') return e.code
  return e?.response?.data?.code
}

export class ApiError extends Error {
  code: number
  detail?: string
  // The server stamps every response with a request id. On a 500 the message is
  // deliberately generic — the real cause is only in the server log — so this is
  // the one thing that lets an operator find it. Dropping it left the user with
  // "Request failed with status code 500" and nothing to quote.
  traceId?: string

  constructor(code: number, message: string, detail?: string, traceId?: string) {
    super(message)
    this.name = 'ApiError'
    this.code = code
    this.detail = detail
    this.traceId = traceId
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
