import type { AxiosRequestConfig } from 'axios'
import { client, portalClient } from './client'
import type { ApiResponse, LoginRequest, LoginResponse, CurrentUser, CaptchaResponse } from '../types'

export const authApi = {
  // Console auth
  captcha: () =>
    client.get<ApiResponse<CaptchaResponse>>('/auth/captcha').then(r => r.data.data),
  login: (data: LoginRequest) =>
    client.post<ApiResponse<LoginResponse>>('/auth/login', data).then(r => r.data.data),
  logout: () =>
    client.post<ApiResponse<null>>('/auth/logout').then(r => r.data),
  me: (cfg?: AxiosRequestConfig) =>
    client.get<ApiResponse<CurrentUser>>('/auth/me', cfg).then(r => r.data.data),
  // Seamless SSO: mint a console session from an existing SSO session (portal
  // login). 403 when the user isn't a console admin → caller falls back to login.
  sso: () =>
    client.post<ApiResponse<null>>('/auth/sso', null, { skipAuthEvent: true }).then(r => r.data),

  // Portal auth
  portalCaptcha: () =>
    portalClient.get<ApiResponse<CaptchaResponse>>('/auth/captcha').then(r => r.data.data),
  portalLogin: (data: LoginRequest) =>
    portalClient.post<ApiResponse<LoginResponse>>('/auth/login', data).then(r => r.data.data),
  portalVerifyMFA: (data: { challenge: string; code: string; remember?: boolean }) =>
    portalClient.post<ApiResponse<LoginResponse>>('/auth/mfa/verify', data).then(r => r.data.data),
  portalLogout: () =>
    portalClient.post<ApiResponse<null>>('/auth/logout').then(r => r.data),
  portalMe: (cfg?: AxiosRequestConfig) =>
    portalClient.get<ApiResponse<CurrentUser>>('/auth/me', cfg).then(r => r.data.data),
  // Seamless SSO: mint a portal session from an existing SSO session (e.g.
  // switching back from console). Open to any authenticated identity.
  portalSso: () =>
    portalClient.post<ApiResponse<null>>('/auth/sso', null, { skipAuthEvent: true }).then(r => r.data),

  // Console MFA (mirrors portal — same engine, different cookie namespace).
  consoleVerifyMFA: (data: { challenge: string; code: string; remember?: boolean }) =>
    client.post<ApiResponse<LoginResponse>>('/auth/mfa/verify', data).then(r => r.data.data),
}
