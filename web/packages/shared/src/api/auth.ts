import type { AxiosRequestConfig } from 'axios'
import { client, portalClient } from './client'
import type { ApiResponse, LoginRequest, LoginResponse, CurrentUser, CaptchaResponse } from '../types'

// StepUpMethod is what the server will accept as proof for this session:
// 'totp' when a factor is enrolled, 'password' when none is but the account has
// a local password, 'none' for an external-IdP account with neither (that one
// has to enroll a factor first).
export type StepUpMethod = 'totp' | 'password' | 'none'

export interface StepUpMethodInfo {
  method: StepUpMethod
}

// StepUpProof carries exactly the field the resolved method asks for. The
// server picks which one it reads — sending a password never satisfies a
// session whose account has a factor enrolled.
export type StepUpProof = { code: string } | { password: string }

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
  // Step-up: re-verify MFA on the current console session to clear a high-risk
  // operation's step_up_required gate. skipAuthEvent so a transient 401 here
  // doesn't bounce the whole console to login.
  stepUp: (code: string) =>
    client.post<ApiResponse<null>>('/auth/step-up', { code }, { skipAuthEvent: true }).then(r => r.data),
  // Which proof the CURRENT session will be challenged for. The server decides
  // from what the account has (a factor → 'totp'; none but a local password →
  // 'password'; neither → 'none'), so the SPA renders the right prompt instead
  // of demanding a TOTP code from an account that has no authenticator.
  stepUpMethod: () =>
    client.get<ApiResponse<StepUpMethodInfo>>('/auth/step-up', { skipAuthEvent: true }).then(r => r.data.data),

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
  // Portal step-up. The portal needs its OWN sudo window: the console route
  // above refreshes the console session, while portal-side gates (the form-fill
  // extension's pair / credential reveal) read the portal session. Without this
  // the window could only be reopened by signing in again.
  portalStepUpMethod: () =>
    portalClient
      .get<ApiResponse<StepUpMethodInfo>>('/auth/step-up', { skipAuthEvent: true })
      .then(r => r.data.data),
  portalStepUp: (proof: StepUpProof) =>
    portalClient
      .post<ApiResponse<null>>('/auth/step-up', proof, { skipAuthEvent: true })
      .then(r => r.data),

  // Console MFA (mirrors portal — same engine, different cookie namespace).
  consoleVerifyMFA: (data: { challenge: string; code: string; remember?: boolean }) =>
    client.post<ApiResponse<LoginResponse>>('/auth/mfa/verify', data).then(r => r.data.data),
}
