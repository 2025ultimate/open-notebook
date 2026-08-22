import { describe, it, expect } from 'vitest'
import { describeFirebaseError } from './firebase'

describe('describeFirebaseError', () => {
  it('stays silent when the user closes the popup', () => {
    // A cancel is not a failure — showing a red error would be wrong.
    expect(
      describeFirebaseError({ code: 'auth/popup-closed-by-user' })
    ).toEqual({ messageKey: null })
    expect(
      describeFirebaseError({ code: 'auth/cancelled-popup-request' })
    ).toEqual({ messageKey: null })
  })

  it('names the actionable failures', () => {
    expect(describeFirebaseError({ code: 'auth/popup-blocked' })).toEqual({
      messageKey: 'auth.popupBlocked',
    })
    expect(describeFirebaseError({ code: 'auth/unauthorized-domain' })).toEqual({
      messageKey: 'auth.unauthorizedDomain',
    })
    expect(
      describeFirebaseError({ code: 'auth/network-request-failed' })
    ).toEqual({ messageKey: 'auth.networkError' })
  })

  it('falls back to the generic message for anything else', () => {
    expect(describeFirebaseError({ code: 'auth/internal-error' })).toEqual({
      messageKey: 'auth.googleSignInFailed',
    })
    expect(describeFirebaseError(new Error('boom'))).toEqual({
      messageKey: 'auth.googleSignInFailed',
    })
    expect(describeFirebaseError(undefined)).toEqual({
      messageKey: 'auth.googleSignInFailed',
    })
  })
})
