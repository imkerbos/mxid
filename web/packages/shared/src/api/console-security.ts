import { client } from './client'
import type {
  ApiResponse,
  MFAInfo,
  SessionInfo,
  IdentityInfo,
} from '../types'

export interface LoginHistoryRow {
  event_type: string
  success: boolean
  ip: string
  user_agent: string
  reason?: string
  created_at: string
}

export interface APITokenRow {
  id: string
  name: string
  prefix: string
  scopes: string[]
  expires_at: string | null
  last_used_at: string | null
  revoked_at: string | null
  created_at: string
  /** populated only on create response */
  plaintext?: string
}

// Console mirror of the portal /security sub-tree. Backend uses the SAME
// handler under the hood; only the cookie namespace differs (console vs
// portal). Change-password kills sessions in BOTH namespaces; the other
// endpoints are scoped to the console namespace.
export const consoleSecurityApi = {
  changePassword: (old_password: string, new_password: string, totp_code?: string) =>
    client.put<ApiResponse<null>>('/security/password', { old_password, new_password, totp_code }).then(r => r.data),
  listMFA: () =>
    client.get<ApiResponse<MFAInfo[]>>('/security/mfa').then(r => r.data.data),
  setupTOTP: () =>
    client.post<ApiResponse<{ secret: string; qr_url: string }>>('/security/mfa/totp/setup').then(r => r.data.data),
  verifyTOTP: (code: string) =>
    client.post<ApiResponse<null>>('/security/mfa/totp/verify', { code }).then(r => r.data),
  deleteTOTP: () =>
    client.delete<ApiResponse<null>>('/security/mfa/totp').then(r => r.data),
  listIdentities: () =>
    client.get<ApiResponse<IdentityInfo[]>>('/security/identities').then(r => r.data.data),
  listSessions: () =>
    client.get<ApiResponse<SessionInfo[]>>('/security/sessions').then(r => r.data.data),
  deleteSession: (sid: string) =>
    client.delete<ApiResponse<null>>(`/security/sessions/${sid}`).then(r => r.data),

  // Login history (audit-backed)
  listLoginHistory: (limit = 50) =>
    client
      .get<ApiResponse<LoginHistoryRow[]>>('/security/login-history', { params: { limit } })
      .then(r => r.data.data),

  // Backup codes — one-shot plaintext is returned by regenerate.
  countBackupCodes: () =>
    client.get<ApiResponse<{ remaining: number }>>('/security/mfa/backup-codes').then(r => r.data.data.remaining),
  regenerateBackupCodes: (totp_code?: string) =>
    client
      .post<ApiResponse<{ codes: string[] }>>('/security/mfa/backup-codes', totp_code ? { totp_code } : {})
      .then(r => r.data.data.codes),

  // API tokens
  listAPITokens: () =>
    client.get<ApiResponse<APITokenRow[]>>('/security/api-tokens').then(r => r.data.data),
  createAPIToken: (data: { name: string; scopes: string[]; expires_in_days: number }) =>
    client.post<ApiResponse<APITokenRow>>('/security/api-tokens', data).then(r => r.data.data),
  revokeAPIToken: (id: string) =>
    client.delete<ApiResponse<null>>(`/security/api-tokens/${id}`).then(r => r.data),

  // Profile
  getProfile: () =>
    client
      .get<ApiResponse<{ user: ConsoleUserInfo; detail: ConsoleUserDetail }>>('/profile')
      .then(r => r.data.data),
  updateProfile: (data: { display_name?: string; phone?: string; email?: string }) =>
    client.put<ApiResponse<null>>('/profile', data).then(r => r.data),
  updateAvatar: (avatar: string) =>
    client.put<ApiResponse<null>>('/profile/avatar', { avatar }).then(r => r.data),
  sendEmailVerification: () =>
    client
      .post<ApiResponse<{ sent: boolean; smtp: boolean; email: string; ttl_seconds: number; dev_link: string }>>(
        '/profile/email/send-verification',
      )
      .then(r => r.data.data),
}

export interface ConsoleUserInfo {
  id: string
  username: string
  email: string
  email_verified: boolean
  phone: string
  display_name: string
  avatar: string
  status: number
  last_login_at: string | null
}

export interface ConsoleUserDetail {
  gender?: number | null
  birthday?: string | null
  address?: string | null
  employee_no?: string | null
  job_title?: string | null
  department?: string | null
}
