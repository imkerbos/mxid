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
  // passwordChangeRequired is set when the backend password gate returns 40333.
  passwordChangeRequired: boolean
  setUser: (user: CurrentUser | null) => void
  setLoading: (loading: boolean) => void
  setMfaEnrollRequired: (required: boolean) => void
  setPasswordChangeRequired: (required: boolean) => void
  clear: () => void
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  loading: true,
  mfaEnrollRequired: false,
  passwordChangeRequired: false,
  setUser: (user) => set({ user, loading: false }),
  setLoading: (loading) => set({ loading }),
  setMfaEnrollRequired: (mfaEnrollRequired) => set({ mfaEnrollRequired }),
  setPasswordChangeRequired: (passwordChangeRequired) => set({ passwordChangeRequired }),
  clear: () => set({ user: null, loading: false, mfaEnrollRequired: false, passwordChangeRequired: false }),
}))
