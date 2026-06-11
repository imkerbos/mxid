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
  me: () =>
    client.get<ApiResponse<CurrentUser>>('/auth/me').then(r => r.data.data),

  // Portal auth
  portalCaptcha: () =>
    portalClient.get<ApiResponse<CaptchaResponse>>('/auth/captcha').then(r => r.data.data),
  portalLogin: (data: LoginRequest) =>
    portalClient.post<ApiResponse<LoginResponse>>('/auth/login', data).then(r => r.data.data),
  portalVerifyMFA: (data: { challenge: string; code: string; remember?: boolean }) =>
    portalClient.post<ApiResponse<LoginResponse>>('/auth/mfa/verify', data).then(r => r.data.data),
  portalLogout: () =>
    portalClient.post<ApiResponse<null>>('/auth/logout').then(r => r.data),
  portalMe: () =>
    portalClient.get<ApiResponse<CurrentUser>>('/auth/me').then(r => r.data.data),

  // Console MFA (mirrors portal — same engine, different cookie namespace).
  consoleVerifyMFA: (data: { challenge: string; code: string; remember?: boolean }) =>
    client.post<ApiResponse<LoginResponse>>('/auth/mfa/verify', data).then(r => r.data.data),
}
