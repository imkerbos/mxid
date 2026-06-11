import { client } from './client'
import type { ApiResponse, PaginatedData, Role, Permission, RoleBinding } from '../types'

export const permissionApi = {
  // Roles
  listRoles: (params: Record<string, unknown>) =>
    client.get<ApiResponse<PaginatedData<Role>>>('/roles', { params }).then(r => r.data.data),
  getRole: (id: string) =>
    client.get<ApiResponse<Role>>(`/roles/${id}`).then(r => r.data.data),
  createRole: (data: { name: string; code: string; description?: string; type?: number }) =>
    client.post<ApiResponse<Role>>('/roles', { ...data, type: data.type ?? 2 }).then(r => r.data.data),
  updateRole: (id: string, data: { name?: string; description?: string }) =>
    client.put<ApiResponse<Role>>(`/roles/${id}`, data).then(r => r.data.data),
  deleteRole: (id: string) =>
    client.delete<ApiResponse<null>>(`/roles/${id}`).then(r => r.data),

  // Role permissions — permission_ids are strings end-to-end.
  getRolePermissions: (roleId: string) =>
    client.get<ApiResponse<Permission[]>>(`/roles/${roleId}/permissions`).then(r => r.data.data),
  setRolePermissions: (roleId: string, permission_ids: string[]) =>
    client.put<ApiResponse<null>>(`/roles/${roleId}/permissions`, { permission_ids }).then(r => r.data),

  // Permissions
  listPermissions: () =>
    client.get<ApiResponse<Permission[]>>('/permissions').then(r => r.data.data),

  // Role members. subject_id and scope_id are string Snowflake IDs.
  listMembers: (roleId: string, params?: Record<string, unknown>) =>
    client.get<ApiResponse<PaginatedData<RoleBinding>>>(`/roles/${roleId}/members`, { params }).then(r => r.data.data),
  addMember: (
    roleId: string,
    data: {
      subject_type: string
      subject_id: string
      scope_type?: 'org' | 'group'
      scope_id?: string
    },
  ) => client.post<ApiResponse<RoleBinding>>(`/roles/${roleId}/members`, data).then(r => r.data.data),
  removeMember: (roleId: string, memberId: string) =>
    client.delete<ApiResponse<null>>(`/roles/${roleId}/members/${memberId}`).then(r => r.data),
}
