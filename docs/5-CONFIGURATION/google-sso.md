# Google Sign-In (Firebase)

Protect your instance with Google accounts instead of a shared password.

---

## What this does — and what it does not

**Does:** replaces the single shared password with "Sign in with Google", restricted to an
email allowlist you control. You can add and remove people without rotating a secret, and
each sign-in is a real, revocable Google session.

**Does not:** give each person their own notebooks. Open Notebook is a single-workspace
tool — everyone who gets in shares the same notebooks, sources and notes, exactly as
everyone who knows the password does today. Per-user data is tracked separately in
[#712](https://github.com/lfnovo/open-notebook/issues/712); see
[ADR-008](../7-DEVELOPMENT/decisions/ADR-008-pluggable-auth-modes.md) for the reasoning.

If you only need *gatekeeping* and you already run a reverse proxy, an auth proxy
(oauth2-proxy, Authelia, Cloudflare Access, Tailscale) in front of the app does the same
job with no configuration here — see [Reverse Proxy](reverse-proxy.md). Firebase mode
exists for operators who don't run one.

> **Password mode remains the default.** Nothing on this page affects an instance that
> doesn't set `OPEN_NOTEBOOK_AUTH_MODE=firebase`, and Firebase mode needs outbound
> internet access to Google. Air-gapped installs should stay on password mode.

---

## Step 1: Create the Firebase project

1. Go to the [Firebase console](https://console.firebase.google.com/) and create a project
   (or reuse one).
2. **Build → Authentication → Get started → Sign-in method → Google → Enable.** Set a
   support email and save.
3. **Project settings (gear icon) → General → Your apps → Add app → Web (`</>`).**
   Register the app; Firebase shows a config snippet. You need three values from it:

   | Snippet field | Environment variable |
   |---|---|
   | `projectId` | `OPEN_NOTEBOOK_FIREBASE_PROJECT_ID` |
   | `apiKey` | `OPEN_NOTEBOOK_FIREBASE_API_KEY` |
   | `authDomain` | `OPEN_NOTEBOOK_FIREBASE_AUTH_DOMAIN` (optional) |

   These are **public identifiers**, not secrets — every Firebase web app ships them in its
   client bundle, and Open Notebook serves them from `GET /api/auth/status` so the login
   page can initialise the SDK. Access is controlled by the allowlist and by authorized
   domains, not by hiding these values.

4. **Authentication → Settings → Authorized domains → Add domain.** Add the hostname you
   reach Open Notebook on (e.g. `notebook.example.com`). `localhost` is authorized by
   default. Sign-in fails with "this domain is not authorized" until you do this.

---

## Step 2: Configure Open Notebook

```bash
OPEN_NOTEBOOK_AUTH_MODE=firebase
OPEN_NOTEBOOK_FIREBASE_PROJECT_ID=my-notebook-project
OPEN_NOTEBOOK_FIREBASE_API_KEY=AIzaSy...
OPEN_NOTEBOOK_FIREBASE_ALLOWED_EMAILS=you@example.com,teammate@example.com

# Optional — defaults to <project-id>.firebaseapp.com
# OPEN_NOTEBOOK_FIREBASE_AUTH_DOMAIN=my-notebook-project.firebaseapp.com
```

Restart the API. The login page now shows a **Sign in with Google** button.

### The allowlist is required

`OPEN_NOTEBOOK_FIREBASE_ALLOWED_EMAILS` is a comma-separated list, matched
case-insensitively against the verified `email` claim. **It cannot be empty.**

A Firebase project with Google sign-in enabled accepts *any* Google account on the
internet — the project doesn't restrict who can authenticate, it only tells you who did.
The allowlist is the thing that keeps strangers out. If it's missing, Open Notebook
**denies every request** and logs the reason at startup, rather than starting up
wide open.

Accounts whose email is unverified are rejected regardless of the allowlist.

### Docker secrets

Every variable above also accepts the `_FILE` suffix, reading the value from a file:

```yaml
environment:
  - OPEN_NOTEBOOK_AUTH_MODE=firebase
  - OPEN_NOTEBOOK_FIREBASE_PROJECT_ID_FILE=/run/secrets/fb_project
  - OPEN_NOTEBOOK_FIREBASE_ALLOWED_EMAILS_FILE=/run/secrets/fb_emails
```

---

## How verification works

The browser signs in with Google and receives a **Firebase ID token** (a JWT). It sends
that token as `Authorization: Bearer <token>`, and the API verifies, on every request:

- the RS256 signature, against Google's published public keys
  (cached per Google's `Cache-Control`, refetched when a key rotates);
- `aud` equals your project id and `iss` is `https://securetoken.google.com/<project-id>`;
- `exp` / `iat` / `sub` are present and the token is not expired;
- `email_verified` is true and `email` is on the allowlist.

No `firebase-admin` SDK and no service-account file are involved — this is a signature
check against a public key set.

ID tokens expire after **one hour**. The frontend asks the Firebase SDK for a current
token on each request, so long sessions keep working without re-authenticating.

---

## Revoking access

Remove the address from `OPEN_NOTEBOOK_FIREBASE_ALLOWED_EMAILS` and restart the API. For
an immediate, project-wide cut-off, also disable or delete the user under
**Firebase console → Authentication → Users**.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Login page says Google sign-in "is not configured correctly" | `OPEN_NOTEBOOK_FIREBASE_PROJECT_ID` or `..._ALLOWED_EMAILS` missing | Set both and restart; the API log names the missing one |
| "This domain is not authorized in the Firebase project" | Hostname missing from Firebase's authorized domains | Authentication → Settings → Authorized domains → Add domain |
| "This Google account is not authorized for this instance" | Signed in with an address that isn't allowlisted | Add it to `OPEN_NOTEBOOK_FIREBASE_ALLOWED_EMAILS`, or sign in with an allowlisted account |
| "The sign-in popup was blocked" | Browser popup blocker | Allow popups for the site and retry |
| Every request 401s, including from the UI | Firebase mode is on but misconfigured — this is fail-closed by design | Check the API startup log |
| Login worked, then stopped after an hour | Token refresh is failing — usually blocked third-party storage | Check the browser console; avoid private-window/strict-tracking modes |

Still stuck? `curl http://localhost:5055/api/auth/status` reports the mode and whether the
server considers itself configured. It never returns the allowlist or any secret.

---

## Related

- [Environment Reference](environment-reference.md) — every variable
- [Security](security.md) — the wider security posture
- [Reverse Proxy](reverse-proxy.md) — the auth-proxy alternative
- [ADR-008](../7-DEVELOPMENT/decisions/ADR-008-pluggable-auth-modes.md) — why it works this way
