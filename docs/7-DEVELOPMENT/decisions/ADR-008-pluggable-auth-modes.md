# ADR-008: Authentication is a pluggable mode; Firebase gates the door without scoping data

- **Status**: Accepted
- **Date**: 2026-08
- **Related**: [#712](https://github.com/lfnovo/open-notebook/issues/712) (multi-user umbrella), [PDR-001](PDR-001-single-user-first.md) (single-user first), [VISION.md](../../../VISION.md) (Privacy first), [Google SSO setup](../../5-CONFIGURATION/google-sso.md)

## Context

Until now the only way to protect an instance was `OPEN_NOTEBOOK_PASSWORD`: one shared secret, compared against the Bearer credential, with the frontend storing that password in `localStorage` as its "token". It works, but a shared password is awkward to rotate, impossible to revoke per person, and gives no record of who opened the door.

Operators asked for Google sign-in. That request is easy to confuse with multi-user, which it is not: Grasp has **no user in its data model** — no `user`, `owner` or `tenant` field exists on any table across all 20 migrations. Every notebook, source and note is global. Authenticating with Google therefore changes *who may enter*, not *what they see*. The multi-user question is still open (#712, PDR-001) and this decision must not pre-empt it.

There is also a standing constraint: VISION.md's privacy principle forbids "a hard dependency on specific cloud services". An instance in an air-gapped network must keep working exactly as before.

## Decision

**Auth is selected by `OPEN_NOTEBOOK_AUTH_MODE`, defaulting to `password`. The new `firebase` mode authenticates identity only — it does not scope data.**

- `password` (default) is byte-for-byte the previous behaviour, including "auth disabled when no password is set". No existing deployment changes.
- `firebase` verifies the Bearer credential as a Firebase ID token against Google's public JWKS, then gates on `OPEN_NOTEBOOK_FIREBASE_ALLOWED_EMAILS`.
- **The allowlist is mandatory.** A Firebase project with Google sign-in enabled accepts *any* Google account, so an empty allowlist would publish the workspace to the internet. Missing or empty config fails closed: every request 401s and the error is logged at startup.
- **No `firebase-admin`.** Verification is an RS256 signature check against a public JWKS, done with `pyjwt[crypto]` over `httpx`. The Admin SDK would pull grpc and google-cloud and want a service-account file on disk.
- **No per-user scoping, deliberately.** Every allowlisted address shares one workspace, exactly as everyone knowing the password does today. The verified email is attached to `request.state` for provenance only — never used as a query key.
- The Firebase JS SDK is behind a dynamic `import()`, so password-mode instances never download it.

## Alternatives considered

- **Put an auth proxy in front (oauth2-proxy, Authelia, Cloudflare Access)** — still the recommended route for operators who run one, and it needs no code. Rejected as the *only* answer: it requires infrastructure many self-hosters don't have, and the docs already assume a single fronted port.
- **`firebase-admin` SDK** — rejected: heavyweight transitive tree and a service-account file, for a public-key signature check. Also awkward in a container that should stay lean (ADR-007's posture).
- **Replace the password mode outright** — rejected: it would make a Google Cloud project a hard dependency of a privacy-first, self-hostable tool, breaking air-gapped installs.
- **Ship Google sign-in *with* per-user data scoping** — rejected: that is #712, a schema-and-query-layer redesign whose product shape (household vs. team vs. SaaS) PDR-001 explicitly leaves undecided. Bundling it into an auth change would decide it by accident.
- **Default the allowlist to "any verified Google account"** — rejected: the friendliest-looking default is a world-readable instance.

## Consequences

- Adding a third mode (OIDC, header-trust from a proxy) is now a branch in one middleware plus a `/auth/status` field, not a rewrite.
- **Firebase mode needs the internet** to fetch Google's JWKS. Keys are cached per the response's `Cache-Control` (clamped to 5 min–24 h) with a rate-limited refetch on an unknown `kid`, so a rotation is picked up without hammering Google.
- **ID tokens expire hourly**, unlike the static password. The frontend now resolves a fresh token per request from the SDK rather than trusting the persisted copy — the token in `localStorage` is a fallback, not the source of truth.
- Misconfiguration is a lockout, by design. The startup log names the missing variable, and `/api/auth/status` reports `configured: false` so the login screen can say so instead of failing silently.
- When #712 is decided, the verified email is already flowing through the middleware — this record should be revisited, not reversed, to add scoping behind it.
