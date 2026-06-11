import { client, portalClient } from './client'
import type { ApiResponse } from '../types'

// ExternalIDP — admin shape with full config + status + auto_create flags.
export interface ExternalIDP {
  id: string
  tenant_id: string
  type: string
  name: string
  code: string
  icon: string | null
  description: string | null
  config: Record<string, unknown>
  status: number
  auto_create: boolean
  default_org_id: string | null
  sort_order: number
  created_at: string
  updated_at: string
}

// PublicIDP — what the portal login page fetches. Identical shape except
// `config` is intentionally blank so secrets never reach the browser.
export type PublicIDP = ExternalIDP

export const externalIdpApi = {
  // Console (admin)
  list: () => client.get<ApiResponse<ExternalIDP[]>>('/external-idps').then(r => r.data.data),
  types: () => client.get<ApiResponse<string[]>>('/external-idps/types').then(r => r.data.data),
  get: (id: string) => client.get<ApiResponse<ExternalIDP>>(`/external-idps/${id}`).then(r => r.data.data),
  create: (data: Record<string, unknown>) =>
    client.post<ApiResponse<ExternalIDP>>('/external-idps', data).then(r => r.data.data),
  update: (id: string, data: Record<string, unknown>) =>
    client.put<ApiResponse<ExternalIDP>>(`/external-idps/${id}`, data).then(r => r.data.data),
  delete: (id: string) =>
    client.delete<ApiResponse<null>>(`/external-idps/${id}`).then(r => r.data),

  // Portal (public) — list enabled IdPs for the login page.
  // tenant: optional tenant code; backend filters the list to that tenant's
  // IdPs only. Used by multi-tenant portals where each enterprise sees
  // only its own social login buttons.
  listPublic: (tenant?: string) =>
    portalClient
      .get<ApiResponse<PublicIDP[]>>('/auth/external', { params: tenant ? { tenant } : undefined })
      .then(r => r.data.data),
  // startURL returns the absolute redirect URL the browser should hit to
  // begin the OAuth dance. The backend issues a 302 from this endpoint, so
  // setting window.location.href is the simplest way to trigger it.
  //
  // tenant: optional code. Sent through to the callback so the
  // post-login session lands in the right tenant.
  startURL: (code: string, returnTo?: string, tenant?: string) => {
    const params = new URLSearchParams()
    if (returnTo) params.set('return_to', returnTo)
    if (tenant) params.set('tenant', tenant)
    const qs = params.toString()
    return `/api/v1/portal/auth/external/${encodeURIComponent(code)}/start${qs ? `?${qs}` : ''}`
  },
}
