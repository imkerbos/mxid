import axios from 'axios'
import type { ApiResponse } from '../types'

// SMS OTP login. Public endpoints — bare axios so the shared client's
// Bearer / CSRF interceptors don't apply to pre-login traffic.

export interface SMSSendResponse {
  sent: boolean
  ttl_seconds: number
  // dev_code populated only when the SMS service isn't configured.
  // Production should never see this set.
  dev_code?: string
}

export interface SMSLoginResponse {
  user_id: string
  username: string
  display_name: string
}

const root = axios.create({ baseURL: '/' })

export const smsOTPApi = {
  send: (phone: string, tenant?: string) =>
    root
      .post<ApiResponse<SMSSendResponse>>('/api/v1/portal-public/auth/sms/send', { phone, tenant })
      .then((r) => r.data.data),
  login: (phone: string, code: string, tenant?: string) =>
    root
      .post<ApiResponse<SMSLoginResponse>>('/api/v1/portal-public/auth/sms/login', { phone, code, tenant })
      .then((r) => r.data.data),
}
