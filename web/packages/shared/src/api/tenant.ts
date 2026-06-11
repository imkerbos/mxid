import { client } from './client'
import type { ApiResponse } from '../types'

export interface Tenant {
  id: string
  name: string
  code: string
  status: number
  config: Record<string, unknown>
  created_at: string
  updated_at: string
}

export const tenantApi = {
  list: () => client.get<ApiResponse<Tenant[]>>('/tenants').then(r => r.data.data),
  get: (id: string) => client.get<ApiResponse<Tenant>>(`/tenants/${id}`).then(r => r.data.data),
  create: (data: { name: string; code: string; status?: number }) =>
    client.post<ApiResponse<Tenant>>('/tenants', data).then(r => r.data.data),
  update: (id: string, data: { name?: string; status?: number }) =>
    client.put<ApiResponse<Tenant>>(`/tenants/${id}`, data).then(r => r.data.data),
  delete: (id: string) =>
    client.delete<ApiResponse<null>>(`/tenants/${id}`).then(r => r.data),
}
