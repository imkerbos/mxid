import axios from 'axios'
import type { ApiResponse } from '../types'

// Magic-link login (passwordless). Public endpoints — bare axios.

export interface MagicLinkSendResponse {
  sent: boolean
  ttl_seconds: number
  // dev_link is populated only when SMTP is unavailable and the email
  // matched a real user. Production should never see this set.
  dev_link?: string
}

const root = axios.create({ baseURL: '/' })

export const magicLinkApi = {
  send: (email: string, tenant?: string) =>
    root
      .post<ApiResponse<MagicLinkSendResponse>>('/api/v1/portal-public/auth/magic-link/send', { email, tenant })
      .then((r) => r.data.data),

  // Callback URL is consumed by full browser navigation, not XHR, because
  // it must set the session cookie + 302 redirect to /apps.
  callbackURL: (token: string, tenant?: string): string => {
    const params = new URLSearchParams({ token })
    if (tenant) params.set('tenant', tenant)
    return `/api/v1/portal-public/auth/magic-link/callback?${params.toString()}`
  },
}
