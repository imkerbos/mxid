import { client } from './client'
import type { ApiResponse, PaginatedData, AuditLog } from '../types'

export const auditApi = {
  list: (params: Record<string, unknown>) =>
    client.get<ApiResponse<PaginatedData<AuditLog>>>('/audit/logs', { params }).then(r => r.data.data),
  stats: (params?: Record<string, unknown>) =>
    client.get<ApiResponse<Record<string, unknown>>>('/audit/stats', { params }).then(r => r.data.data),
}
