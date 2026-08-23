import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { getAuthToken, resolveAuthToken } from './auth-token'

const FIREBASE_CONFIG = {
  project_id: 'demo-notebook',
  api_key: 'web-api-key',
  auth_domain: 'demo-notebook.firebaseapp.com',
}

const getFreshIdToken = vi.fn()

vi.mock('@/lib/firebase', () => ({
  getFreshIdToken: (...args: unknown[]) => getFreshIdToken(...args),
}))

function persist(state: Record<string, unknown>) {
  window.localStorage.setItem('auth-storage', JSON.stringify({ state }))
}

describe('auth-token', () => {
  beforeEach(() => {
    window.localStorage.clear()
    getFreshIdToken.mockReset()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('getAuthToken', () => {
    it('returns null when nothing is stored', () => {
      expect(getAuthToken()).toBeNull()
    })

    it('returns null (and does not throw) on corrupt storage', () => {
      vi.spyOn(console, 'error').mockImplementation(() => {})
      window.localStorage.setItem('auth-storage', 'not json')
      expect(getAuthToken()).toBeNull()
    })

    it('reads the persisted token', () => {
      persist({ token: 'hunter2' })
      expect(getAuthToken()).toBe('hunter2')
    })
  })

  describe('resolveAuthToken', () => {
    it('returns the stored password unchanged in password mode', async () => {
      persist({ token: 'hunter2', authMode: 'password' })

      await expect(resolveAuthToken()).resolves.toBe('hunter2')
      expect(getFreshIdToken).not.toHaveBeenCalled()
    })

    it('does not reach for Firebase when no mode is recorded', async () => {
      persist({ token: 'hunter2' })

      await expect(resolveAuthToken()).resolves.toBe('hunter2')
      expect(getFreshIdToken).not.toHaveBeenCalled()
    })

    it('mints a fresh ID token in firebase mode', async () => {
      // The stored token is an hour-old ID token; the SDK holds the current one.
      persist({
        token: 'stale-id-token',
        authMode: 'firebase',
        firebaseConfig: FIREBASE_CONFIG,
      })
      getFreshIdToken.mockResolvedValue('fresh-id-token')

      await expect(resolveAuthToken()).resolves.toBe('fresh-id-token')
      expect(getFreshIdToken).toHaveBeenCalledWith(FIREBASE_CONFIG)
    })

    it('falls back to the stored token when the SDK cannot answer', async () => {
      persist({
        token: 'stored-id-token',
        authMode: 'firebase',
        firebaseConfig: FIREBASE_CONFIG,
      })
      getFreshIdToken.mockResolvedValue(null)

      // Better a possibly-stale token the server can reject than an
      // unauthenticated request.
      await expect(resolveAuthToken()).resolves.toBe('stored-id-token')
    })

    it('skips the refresh when firebase mode has no config yet', async () => {
      persist({ token: 'stored-id-token', authMode: 'firebase' })

      await expect(resolveAuthToken()).resolves.toBe('stored-id-token')
      expect(getFreshIdToken).not.toHaveBeenCalled()
    })
  })
})
