# Security Model

Cloudflare Access Passkeys Kit has the following security properties:

- Passkeys are the only enabled interactive sign-in method.
- Enrollment requires a cryptographically random, expiring, single-use invitation.
- The public request form always returns the same “If authorized” response. A per-IP rate limiter runs first, before the request body is read or the policy is looked up; Turnstile can optionally run there as an additional gate.
- Enrollment eligibility comes directly from one reusable Cloudflare Access Allow policy. Only exact Email selectors are accepted; unsupported policy shapes fail closed.
- Invitation email is transactional, includes HTML and plain-text bodies, and is sent through the native Cloudflare Email Service binding.
- Resident credentials and user verification are required. The WebAuthn verification result is checked explicitly for the UV flag.
- Sign-in is usernameless and opens the browser or operating system’s account chooser for discoverable passkeys.
- Passkeys are email-bound: they are labeled with the policy-authorized invitation email instead of a generic “Primary passkey” name.
- Dynamic OAuth client registration and user-managed OAuth client CRUD are disabled.
- Exactly one confidential OIDC client can be provisioned. It requires PKCE, skips consent, and supports only the authorization-code grant.
- OIDC ID tokens use RS256 because Cloudflare Access does not support Better Auth’s default Ed25519/OKP signing keys. The included migration removes incompatible legacy keys when upgrading an existing deployment so Better Auth can generate an RSA key.
- When `PUBLIC_ORIGIN` is set, the Worker serves only that origin, so the admin channel is not reachable on `*.workers.dev` and passkeys, issuer, and invitation links cannot vary by request host.
- Error logs redact invitation tokens from `/invite/<token>` paths.
- Administration requires a separate high-entropy bearer token and exposes no browser dashboard.
- Lost-passkey recovery is destructive and CLI-only: every existing passkey, session, and OAuth token is revoked before a new invitation is issued.

D1 is the system of record. KV is not required for correctness and should not replace D1 for relational authentication state.
