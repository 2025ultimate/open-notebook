// Reads the auth state persisted by the zustand auth store
// (localStorage key `auth-storage`, written by `src/lib/stores/auth-store.ts`).
// Single source of truth for the token-parsing ritual — use this instead of
// re-reading localStorage directly.
import type { FirebaseWebConfig } from '@/lib/firebase'

interface PersistedAuthState {
  token?: string | null
  authMode?: string | null
  firebaseConfig?: FirebaseWebConfig | null
}

function readPersistedAuthState(): PersistedAuthState | null {
  if (typeof window === 'undefined') {
    return null
  }

  const raw = window.localStorage.getItem('auth-storage')
  if (!raw) {
    return null
  }

  try {
    const { state } = JSON.parse(raw)
    return (state ?? null) as PersistedAuthState | null
  } catch (error) {
    console.error('Error parsing auth storage:', error)
    return null
  }
}

export function getAuthToken(): string | null {
  return readPersistedAuthState()?.token ?? null
}

/**
 * The token to send on the next request.
 *
 * In password mode this is the stored password, unchanged. In firebase mode
 * the stored value is a Firebase ID token that expires after an hour, so we
 * ask the SDK for a current one instead — it refreshes transparently when the
 * cached token is close to expiry. Falls back to the stored token whenever the
 * SDK cannot answer (not yet initialised, persistence unavailable), which keeps
 * a request from silently going out unauthenticated.
 *
 * Async because the refresh is: every caller is already inside an async
 * request path.
 */
export async function resolveAuthToken(): Promise<string | null> {
  const state = readPersistedAuthState()
  if (!state) {
    return null
  }

  if (state.authMode === 'firebase' && state.firebaseConfig) {
    const { getFreshIdToken } = await import('@/lib/firebase')
    const fresh = await getFreshIdToken(state.firebaseConfig)
    if (fresh) {
      return fresh
    }
  }

  return state.token ?? null
}
