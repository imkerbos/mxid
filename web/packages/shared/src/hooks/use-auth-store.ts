import { create } from 'zustand'
import type { CurrentUser } from '../types'

interface AuthState {
  user: CurrentUser | null
  loading: boolean
  setUser: (user: CurrentUser | null) => void
  setLoading: (loading: boolean) => void
  clear: () => void
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  loading: true,
  setUser: (user) => set({ user, loading: false }),
  setLoading: (loading) => set({ loading }),
  clear: () => set({ user: null, loading: false }),
}))
