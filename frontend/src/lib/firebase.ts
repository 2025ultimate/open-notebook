/**
 * Firebase Google sign-in for the optional `firebase` auth mode.
 *
 * Everything here is behind a dynamic `import()` on purpose: most Open Notebook
 * instances run in password mode, and they must not pay for the Firebase SDK in
 * their bundle. Next.js code-splits these imports, so the chunk is only fetched
 * once an instance actually reports `auth_mode: "firebase"`.
 *
 * The web config (project id, web API key, auth domain) comes from
 * GET /api/auth/status. Those are public identifiers — Firebase web apps ship
 * them in client bundles — not secrets.
 */

import type { Auth, User } from 'firebase/auth'

export interface FirebaseWebConfig {
  project_id: string
  api_key: string
  auth_domain: string
}

let authPromise: Promise<Auth> | null = null
let authPromiseKey: string | null = null

function configKey(config: FirebaseWebConfig): string {
  return `${config.project_id}|${config.api_key}|${config.auth_domain}`
}

/**
 * Initialise (once) and return the Firebase Auth instance.
 *
 * Re-initialises only if the server reports a different project, which happens
 * when an operator repoints the instance — otherwise the cached promise is
 * reused so concurrent callers share one initialisation.
 */
export async function getFirebaseAuth(config: FirebaseWebConfig): Promise<Auth> {
  const key = configKey(config)
  if (authPromise && authPromiseKey === key) {
    return authPromise
  }

  authPromiseKey = key
  authPromise = (async () => {
    const { initializeApp, getApps, getApp } = await import('firebase/app')
    const { getAuth, setPersistence, browserLocalPersistence } = await import(
      'firebase/auth'
    )

    const options = {
      apiKey: config.api_key,
      authDomain: config.auth_domain,
      projectId: config.project_id,
    }
    const app = getApps().length > 0 ? getApp() : initializeApp(options)
    const auth = getAuth(app)

    // Survive a page reload; without this the user re-authenticates on every
    // refresh, which is jarring for a tool people leave open all day.
    try {
      await setPersistence(auth, browserLocalPersistence)
    } catch (error) {
      // Private browsing modes can refuse persistence — sign-in still works
      // for the current tab, so this is not fatal.
      console.warn('Could not enable Firebase auth persistence:', error)
    }

    return auth
  })()

  return authPromise
}

/**
 * Resolve once the SDK has restored any persisted session.
 *
 * `auth.currentUser` is null immediately after page load even when a valid
 * session exists, so reading it directly would spuriously log the user out.
 */
async function waitForUser(auth: Auth): Promise<User | null> {
  if (auth.currentUser) {
    return auth.currentUser
  }
  const { onAuthStateChanged } = await import('firebase/auth')
  return new Promise<User | null>((resolve) => {
    const unsubscribe = onAuthStateChanged(auth, (user) => {
      unsubscribe()
      resolve(user)
    })
  })
}

export interface GoogleSignInResult {
  token: string
  email: string | null
}

export interface FirebaseErrorDescription {
  /**
   * i18n key to display, or null when there is nothing worth saying (the user
   * closed the popup themselves — a cancel, not a failure).
   */
  messageKey: string | null
}

/**
 * Map a Firebase error onto a translatable message.
 *
 * Keys are written out in full rather than assembled from the error code:
 * the i18n parity test greps the source for literal key strings, and a
 * templated `auth.${code}` would read as an unused translation.
 */
export function describeFirebaseError(error: unknown): FirebaseErrorDescription {
  const code =
    typeof error === 'object' && error !== null && 'code' in error
      ? String((error as { code: unknown }).code)
      : ''

  switch (code) {
    case 'auth/popup-blocked':
      return { messageKey: 'auth.popupBlocked' }
    case 'auth/popup-closed-by-user':
    case 'auth/cancelled-popup-request':
      return { messageKey: null }
    case 'auth/unauthorized-domain':
      return { messageKey: 'auth.unauthorizedDomain' }
    case 'auth/network-request-failed':
      return { messageKey: 'auth.networkError' }
    default:
      return { messageKey: 'auth.googleSignInFailed' }
  }
}

export async function signInWithGoogle(
  config: FirebaseWebConfig
): Promise<GoogleSignInResult> {
  const auth = await getFirebaseAuth(config)
  const { GoogleAuthProvider, signInWithPopup } = await import('firebase/auth')

  const provider = new GoogleAuthProvider()
  // Always show the chooser: on shared machines silently reusing the last
  // Google account is a surprising way to land in someone else's notebooks.
  provider.setCustomParameters({ prompt: 'select_account' })

  const result = await signInWithPopup(auth, provider)
  const token = await result.user.getIdToken()
  return { token, email: result.user.email }
}

/**
 * Current Firebase ID token, refreshed if it is close to expiry.
 *
 * Firebase ID tokens last one hour. `getIdToken()` returns the cached token
 * until roughly five minutes before expiry and transparently mints a new one
 * after that, which is what keeps long-lived sessions working without the
 * request layer having to track expiry itself.
 */
export async function getFreshIdToken(
  config: FirebaseWebConfig
): Promise<string | null> {
  try {
    const auth = await getFirebaseAuth(config)
    const user = await waitForUser(auth)
    if (!user) {
      return null
    }
    return await user.getIdToken()
  } catch (error) {
    console.error('Could not refresh the Firebase ID token:', error)
    return null
  }
}

export async function firebaseSignOut(config: FirebaseWebConfig): Promise<void> {
  try {
    const auth = await getFirebaseAuth(config)
    const { signOut } = await import('firebase/auth')
    await signOut(auth)
  } catch (error) {
    // A failed remote sign-out must not strand the user in the UI; the local
    // store is cleared by the caller regardless.
    console.error('Firebase sign-out failed:', error)
  }
}
