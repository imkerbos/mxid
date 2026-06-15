import axios from 'axios'
import type { ApiResponse } from '../types'

// Portal password-reset flow. Public (pre-auth) so we use a bare axios
// instance — the shared `client` carries Bearer / CSRF interceptors that
// would be inappropriate before login.

export interface ForgotResponse {
  sent: boolean
  ttl_seconds: number
  // dev_link is populated only when SMTP is not configured and the email
  // matched a real user; the UI surfaces it as a "click here" link in dev
  // so first-deploy admins can complete the flow without SMTP.
  dev_link?: string
}

const root = axios.create({ baseURL: '/' })

export const passwordResetApi = {
  forgot: (email: string, tenant?: string) =>
    root
      .post<ApiResponse<ForgotResponse>>('/api/v1/portal-public/password/forgot', { email, tenant })
      .then((r) => r.data.data),

  reset: (token: string, newPassword: string) =>
    root
      .post<ApiResponse<{ reset: boolean }>>('/api/v1/portal-public/password/reset', {
        token,
        new_password: newPassword,
      })
      .then((r) => r.data.data),
}
