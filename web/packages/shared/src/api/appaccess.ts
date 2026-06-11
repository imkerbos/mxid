import { client } from './client'
import type { ApiResponse } from '../types'

export type AccessSubjectType = 'public' | 'user' | 'group' | 'org' | 'role'
export type AccessEffect = 'allow' | 'deny'

export interface AccessPolicy {
  id: string
  app_id: string
  tenant_id: string
  subject_type: AccessSubjectType
  subject_id: string
  effect: AccessEffect
  created_at: string
  subject_name?: string
  subject_code?: string
}

// Owner = which side of the policy is being managed:
//   app       → /apps/:id/access-policies         (rules attached to a single app)
//   app-group → /app-groups/:id/access-policies   (rules inherited by every app in the group)
export type AccessOwner = 'app' | 'app-group'

function path(owner: AccessOwner, ownerId: string | number, suffix = '') {
  const base = owner === 'app' ? '/apps' : '/app-groups'
  return `${base}/${ownerId}/access-policies${suffix}`
}

export const appAccessApi = {
  list: (owner: AccessOwner, ownerId: string | number) =>
    client.get<ApiResponse<AccessPolicy[]>>(path(owner, ownerId)).then(r => r.data.data),
  create: (
    owner: AccessOwner,
    ownerId: string | number,
    body: { subject_type: AccessSubjectType; subject_id?: string; effect?: AccessEffect },
  ) =>
    client.post<ApiResponse<AccessPolicy>>(path(owner, ownerId), body).then(r => r.data.data),
  remove: (owner: AccessOwner, ownerId: string | number, policyId: string) =>
    client.delete<ApiResponse<{ deleted: boolean }>>(path(owner, ownerId, `/${policyId}`)).then(r => r.data),
}
