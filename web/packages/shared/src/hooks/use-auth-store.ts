import { create } from 'zustand'
import type { CurrentUser } from '../types'

interface AuthState {
  user: CurrentUser | null
  loading: boolean
  // mfaEnrollRequired is set when the backend enroll gate returns 40331 (policy
  // requires MFA but the user holds no factor). The SPA renders a blocking
  // enrollment screen while true — every other route/API would 403 until a
  // factor is bound, so partial pages must not render.
  mfaEnrollRequired: boolean
  setUser: (user: CurrentUser | null) => void
  setLoading: (loading: boolean) => void
  setMfaEnrollRequired: (required: boolean) => void
  clear: () => void
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  loading: true,
  mfaEnrollRequired: false,
  setUser: (user) => set({ user, loading: false }),
  setLoading: (loading) => set({ loading }),
  setMfaEnrollRequired: (mfaEnrollRequired) => set({ mfaEnrollRequired }),
  clear: () => set({ user: null, loading: false, mfaEnrollRequired: false }),
}))
