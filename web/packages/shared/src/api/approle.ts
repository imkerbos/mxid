import { client } from './client'
import type { ApiResponse } from '../types'

export interface AppRole {
  id: string
  app_id: string
  tenant_id: string
  code: string
  name: string
  description?: string
  is_default: boolean
  sort_order: number
  created_at: string
}

export type AppRoleSubjectType = 'user' | 'group' | 'org' | 'role'

export interface AppRoleBinding {
  id: string
  app_id: string
  tenant_id: string
  app_role_id: string
  subject_type: AppRoleSubjectType
  subject_id: string
  created_at: string
  role_code: string
  role_name: string
  subject_name?: string
  subject_code?: string
}

// Owner = which side owns the role/binding:
//   'app'       → /apps/:id/...
//   'app-group' → /app-groups/:id/...
export type AppRoleOwner = 'app' | 'app-group'

// Reverse view returned by GET /groups/:id/app-role-bindings.
export interface ReverseAppRoleBinding {
  id: string
  app_id?: string
  app_group_id?: string
  tenant_id: string
  app_role_id: string
  subject_type: AppRoleSubjectType
  subject_id: string
  created_at: string
  role_code: string
  role_name: string
  target_type: 'app' | 'app-group'
  target_id: string
  target_name: string
  target_code: string
}

function basePath(owner: AppRoleOwner, ownerId: string | number) {
  const root = owner === 'app' ? '/apps' : '/app-groups'
  return `${root}/${ownerId}`
}

export const appRoleApi = {
  // Roles
  listRoles: (owner: AppRoleOwner, ownerId: string | number) =>
    client.get<ApiResponse<AppRole[]>>(`${basePath(owner, ownerId)}/roles`).then(r => r.data.data),
  createRole: (
    owner: AppRoleOwner,
    ownerId: string | number,
    body: { code: string; name: string; description?: string; is_default?: boolean; sort_order?: number },
  ) =>
    client.post<ApiResponse<AppRole>>(`${basePath(owner, ownerId)}/roles`, body).then(r => r.data.data),
  updateRole: (
    owner: AppRoleOwner,
    ownerId: string | number,
    roleId: string,
    body: { name?: string; description?: string; is_default?: boolean; sort_order?: number },
  ) =>
    client.put<ApiResponse<AppRole>>(`${basePath(owner, ownerId)}/roles/${roleId}`, body).then(r => r.data.data),
  deleteRole: (owner: AppRoleOwner, ownerId: string | number, roleId: string) =>
    client.delete<ApiResponse<{ deleted: boolean }>>(`${basePath(owner, ownerId)}/roles/${roleId}`).then(r => r.data),

  // Bindings
  listBindings: (owner: AppRoleOwner, ownerId: string | number) =>
    client.get<ApiResponse<AppRoleBinding[]>>(`${basePath(owner, ownerId)}/role-bindings`).then(r => r.data.data),
  createBinding: (
    owner: AppRoleOwner,
    ownerId: string | number,
    body: { app_role_id: string; subject_type: AppRoleSubjectType; subject_id: string },
  ) =>
    client.post<ApiResponse<AppRoleBinding>>(`${basePath(owner, ownerId)}/role-bindings`, body).then(r => r.data.data),
  deleteBinding: (owner: AppRoleOwner, ownerId: string | number, bindingId: string) =>
    client.delete<ApiResponse<{ deleted: boolean }>>(`${basePath(owner, ownerId)}/role-bindings/${bindingId}`).then(r => r.data),

  // Reverse views — used by user-group / user pages.
  listBindingsForUserGroup: (groupId: string | number) =>
    client.get<ApiResponse<ReverseAppRoleBinding[]>>(`/groups/${groupId}/app-role-bindings`).then(r => r.data.data),
  listBindingsForUser: (userId: string | number) =>
    client.get<ApiResponse<ReverseAppRoleBinding[]>>(`/users/${userId}/app-role-bindings`).then(r => r.data.data),

  // App-group aggregation: per-member-app role catalog + bindings.
  listMemberAppsRoles: (groupId: string | number) =>
    client.get<ApiResponse<MemberAppRoles[]>>(`/app-groups/${groupId}/member-apps-roles`).then(r => r.data.data),
}

export interface MemberAppRoles {
  app_id: string
  app_name: string
  app_code: string
  roles: AppRole[]
  bindings: AppRoleBinding[]
}
