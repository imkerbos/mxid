import { client } from './client'
import type {
  ApiResponse,
  PaginatedData,
  Group,
  GroupMember,
  BatchMembersResult,
  GroupRule,
  RuleExpr,
  SyncReport,
} from '../types'

export const groupApi = {
  list: (params: Record<string, unknown>) =>
    client.get<ApiResponse<PaginatedData<Group>>>('/groups', { params }).then(r => r.data.data),
  getById: (id: string) =>
    client.get<ApiResponse<Group>>(`/groups/${id}`).then(r => r.data.data),
  create: (data: { name: string; code: string; description?: string }) =>
    client.post<ApiResponse<Group>>('/groups', data).then(r => r.data.data),
  update: (id: string, data: { name?: string; description?: string }) =>
    client.put<ApiResponse<Group>>(`/groups/${id}`, data).then(r => r.data.data),
  // delete with force=true cascades members; without force the API returns 409
  // when the group still has members.
  delete: (id: string, force = false) =>
    client.delete<ApiResponse<null>>(`/groups/${id}`, { params: force ? { force: 'true' } : undefined }).then(r => r.data),
  listMembers: (id: string, params?: Record<string, unknown>) =>
    client.get<ApiResponse<PaginatedData<GroupMember>>>(`/groups/${id}/members`, { params }).then(r => r.data.data),
  addMember: (id: string, user_id: string) =>
    client.post<ApiResponse<null>>(`/groups/${id}/members`, { user_id }).then(r => r.data),
  // Batch endpoints expect string IDs because backend cannot decode []int64
  // from JSON `["123","456"]` (encoding/json `,string` tag does not propagate
  // into slice elements). Callers should map their IDs through `String(...)`
  // before passing the array.
  batchAddMembers: (id: string, user_ids: string[]) =>
    client.post<ApiResponse<BatchMembersResult>>(`/groups/${id}/members/batch`, { user_ids }).then(r => r.data.data),
  removeMember: (id: string, userId: string) =>
    client.delete<ApiResponse<null>>(`/groups/${id}/members/${userId}`).then(r => r.data),
  batchRemoveMembers: (id: string, user_ids: string[]) =>
    client.delete<ApiResponse<BatchMembersResult>>(`/groups/${id}/members/batch`, { data: { user_ids } }).then(r => r.data.data),
  // List every group a user belongs to.
  listByUser: (userId: string) =>
    client.get<ApiResponse<Group[]>>(`/users/${userId}/groups`).then(r => r.data.data),

  // Dynamic group rules.
  ruleFields: () =>
    client.get<ApiResponse<Record<string, string[]>>>(`/groups/rule-fields`).then(r => r.data.data),
  getRule: (id: string) =>
    client.get<ApiResponse<GroupRule>>(`/groups/${id}/rule`).then(r => r.data.data),
  upsertRule: (id: string, expr: RuleExpr) =>
    client.put<ApiResponse<GroupRule>>(`/groups/${id}/rule`, expr).then(r => r.data.data),
  deleteRule: (id: string) =>
    client.delete<ApiResponse<null>>(`/groups/${id}/rule`).then(r => r.data),
  syncRule: (id: string) =>
    client.post<ApiResponse<SyncReport>>(`/groups/${id}/sync`).then(r => r.data.data),
}
