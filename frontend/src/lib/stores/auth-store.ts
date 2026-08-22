import axios from 'axios'
import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import apiClient from '@/lib/api/client'
import { getApiUrl } from '@/lib/config'
import type { FirebaseWebConfig } from '@/lib/firebase'

export type AuthMode = 'password' | 'firebase'

interface AuthState {
  isAuthenticated: boolean
  token: string | null
  isLoading: boolean
  error: string | null
  lastAuthCheck: number | null
  isCheckingAuth: boolean
  hasHydrated: boolean
  authRequired: boolean | null
  /** How this instance authenticates. Null until /auth/status has answered. */
  authMode: AuthMode | null
  /** Public Firebase web config, present only in firebase mode. */
  firebaseConfig: FirebaseWebConfig | null
  /** False when the server reports firebase mode but cannot serve it. */
  authConfigured: boolean
  setHasHydrated: (state: boolean) => void
  checkAuthRequired: () => Promise<boolean>
  login: (password: string) => Promise<boolean>
  loginWithGoogle: () => Promise<boolean>
  logout: () => void
  checkAuth: () => Promise<boolean>
}

interface AuthStatusResponse {
  auth_enabled?: boolean
  auth_mode?: string
  configured?: boolean
  firebase?: FirebaseWebConfig
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      isAuthenticated: false,
      token: null,
      isLoading: false,
      error: null,
      lastAuthCheck: null,
      isCheckingAuth: false,
      hasHydrated: false,
      authRequired: null,
      authMode: null,
      firebaseConfig: null,
      authConfigured: true,

      setHasHydrated: (state: boolean) => {
        set({ hasHydrated: state })
      },

      checkAuthRequired: async () => {
        try {
          const response = await apiClient.get<AuthStatusResponse>('/auth/status', {
            headers: { 'Cache-Control': 'no-store' },
          })

          const required = response.data.auth_enabled || false
          const mode: AuthMode =
            response.data.auth_mode === 'firebase' ? 'firebase' : 'password'
          set({
            authRequired: required,
            authMode: mode,
            authConfigured: response.data.configured !== false,
            firebaseConfig: response.data.firebase ?? null,
          })

          // If auth is not required, mark as authenticated
          if (!required) {
            set({ isAuthenticated: true, token: 'not-required' })
          }

          return required
        } catch (error) {
          console.error('Failed to check auth status:', error)

          // If it's a network error, set a more helpful error message
          if (axios.isAxiosError(error) && !error.response) {
            set({
              error: 'Unable to connect to server. Please check if the API is running.',
              authRequired: null  // Don't assume auth is required if we can't connect
            })
          } else {
            // For other errors, default to requiring auth to be safe
            set({ authRequired: true })
          }

          // Re-throw the error so the UI can handle it
          throw error
        }
      },

      login: async (password: string) => {
        set({ isLoading: true, error: null })
        try {
          const apiUrl = await getApiUrl()

          // Deliberately raw fetch (not apiClient): this probes a candidate
          // password, so the interceptors must not overwrite the Authorization
          // header with the stored token or hard-redirect on 401.
          const response = await fetch(`${apiUrl}/api/notebooks`, {
            method: 'GET',
            headers: {
              'Authorization': `Bearer ${password}`,
              'Content-Type': 'application/json'
            }
          })
          
          if (response.ok) {
            set({ 
              isAuthenticated: true, 
              token: password, 
              isLoading: false,
              lastAuthCheck: Date.now(),
              error: null
            })
            return true
          } else {
            let errorMessage = 'Authentication failed'
            if (response.status === 401) {
              errorMessage = 'Invalid password. Please try again.'
            } else if (response.status === 403) {
              errorMessage = 'Access denied. Please check your credentials.'
            } else if (response.status >= 500) {
              errorMessage = 'Server error. Please try again later.'
            } else {
              errorMessage = `Authentication failed (${response.status})`
            }
            
            set({ 
              error: errorMessage,
              isLoading: false,
              isAuthenticated: false,
              token: null
            })
            return false
          }
        } catch (error) {
          console.error('Network error during auth:', error)
          let errorMessage = 'Authentication failed'
          
          if (error instanceof TypeError && error.message.includes('Failed to fetch')) {
            errorMessage = 'Unable to connect to server. Please check if the API is running.'
          } else if (error instanceof Error) {
            errorMessage = `Network error: ${error.message}`
          } else {
            errorMessage = 'An unexpected error occurred during authentication'
          }
          
          set({ 
            error: errorMessage,
            isLoading: false,
            isAuthenticated: false,
            token: null
          })
          return false
        }
      },
      
      loginWithGoogle: async () => {
        const { firebaseConfig } = get()
        if (!firebaseConfig) {
          set({ error: 'auth.firebaseNotConfigured', isLoading: false })
          return false
        }

        set({ isLoading: true, error: null })
        try {
          const { signInWithGoogle, describeFirebaseError, firebaseSignOut } =
            await import('@/lib/firebase')

          let token: string
          try {
            const result = await signInWithGoogle(firebaseConfig)
            token = result.token
          } catch (error) {
            // messageKey is null when the user simply closed the popup — a
            // cancel, not a failure worth shouting about.
            const { messageKey } = describeFirebaseError(error)
            set({
              error: messageKey,
              isLoading: false,
              isAuthenticated: false,
            })
            return false
          }

          // Google says who they are; the server decides whether that identity
          // is on the allowlist. Probe before claiming success, so a rejected
          // account sees the reason here instead of a broken app shell.
          const apiUrl = await getApiUrl()
          const response = await fetch(`${apiUrl}/api/notebooks`, {
            method: 'GET',
            headers: {
              Authorization: `Bearer ${token}`,
              'Content-Type': 'application/json',
            },
          })

          if (response.ok) {
            set({
              isAuthenticated: true,
              token,
              isLoading: false,
              lastAuthCheck: Date.now(),
              error: null,
            })
            return true
          }

          // Not allowlisted (or the server rejected the token): drop the
          // Firebase session too, otherwise the next attempt silently reuses
          // the same rejected account.
          await firebaseSignOut(firebaseConfig)
          set({
            error:
              response.status === 401 || response.status === 403
                ? 'auth.notAuthorized'
                : 'auth.googleSignInFailed',
            isLoading: false,
            isAuthenticated: false,
            token: null,
          })
          return false
        } catch (error) {
          console.error('Google sign-in error:', error)
          set({
            error: 'auth.googleSignInFailed',
            isLoading: false,
            isAuthenticated: false,
            token: null,
          })
          return false
        }
      },

      logout: () => {
        const { authMode, firebaseConfig } = get()
        if (authMode === 'firebase' && firebaseConfig) {
          void import('@/lib/firebase').then(({ firebaseSignOut }) =>
            firebaseSignOut(firebaseConfig)
          )
        }
        set({
          isAuthenticated: false,
          token: null,
          error: null
        })
      },
      
      checkAuth: async () => {
        const state = get()
        const { token, lastAuthCheck, isCheckingAuth, isAuthenticated } = state

        // If already checking, return current auth state
        if (isCheckingAuth) {
          return isAuthenticated
        }

        // If no token, not authenticated
        if (!token) {
          return false
        }

        // If we checked recently (within 30 seconds) and are authenticated, skip
        const now = Date.now()
        if (isAuthenticated && lastAuthCheck && (now - lastAuthCheck) < 30000) {
          return true
        }

        set({ isCheckingAuth: true })

        try {
          const apiUrl = await getApiUrl()

          // In firebase mode the stored token expires after an hour, so ask
          // the SDK for a current one rather than re-checking a stale token
          // and concluding the session is dead.
          let bearer = token
          const { authMode, firebaseConfig } = state
          if (authMode === 'firebase' && firebaseConfig) {
            const { getFreshIdToken } = await import('@/lib/firebase')
            const fresh = await getFreshIdToken(firebaseConfig)
            if (!fresh) {
              set({
                isAuthenticated: false,
                token: null,
                lastAuthCheck: null,
                isCheckingAuth: false,
              })
              return false
            }
            bearer = fresh
          }

          // Deliberately raw fetch (not apiClient): a 401 here must update
          // store state, not trigger the interceptor's storage-clear/redirect.
          const response = await fetch(`${apiUrl}/api/notebooks`, {
            method: 'GET',
            headers: {
              'Authorization': `Bearer ${bearer}`,
              'Content-Type': 'application/json'
            }
          })

          if (response.ok && bearer !== token) {
            // Keep the persisted copy current for the non-apiClient callers.
            set({ token: bearer })
          }

          if (response.ok) {
            set({ 
              isAuthenticated: true, 
              lastAuthCheck: now,
              isCheckingAuth: false 
            })
            return true
          } else {
            set({
              isAuthenticated: false,
              token: null,
              lastAuthCheck: null,
              isCheckingAuth: false
            })
            return false
          }
        } catch (error) {
          console.error('checkAuth error:', error)
          set({ 
            isAuthenticated: false, 
            token: null,
            lastAuthCheck: null,
            isCheckingAuth: false 
          })
          return false
        }
      }
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({
        token: state.token,
        isAuthenticated: state.isAuthenticated,
        // Persisted so `resolveAuthToken()` (src/lib/auth-token.ts) can mint a
        // fresh Firebase ID token on the first request after a page reload,
        // before this store has had a chance to re-fetch /auth/status.
        authMode: state.authMode,
        firebaseConfig: state.firebaseConfig
      }),
      onRehydrateStorage: () => (state) => {
        state?.setHasHydrated(true)
      }
    }
  )
)