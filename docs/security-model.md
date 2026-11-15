# Security Model

Cloudflare Access Passkeys Kit has the following security properties:

- Passkeys are the only enabled interactive sign-in method.
- There is no separate administrator, admin API or admin CLI. Whoever can configure and deploy the Worker chooses the Access groups in `ACCESS_GROUP_IDS`; whoever can edit those groups in Cloudflare decides who is on them.
- Enrollment and recovery require a cryptographically random, expiring, single-use link sent by email. An invitation link (no passkey yet) is valid 7 days; a recovery link (passkey exists) is valid 1 day.
- The public request form always returns the same “If this address is eligible” response. A per-IP rate limiter runs first, before the request body is read. Turnstile, when enabled, runs next and depends only on the token, never on the address. Address-dependent work runs after the response is decided.
- Each address can request a link once per 10 minutes. The key is an HMAC of the address with any `+tag` ignored, so the database holds no addresses for this.
- Eligibility comes only from the Access groups named in the `ACCESS_GROUP_IDS` variable (not a secret): up to 10 ids, each 32 hexadecimal digits with or without UUID hyphens. Malformed entries and ids after the tenth are ignored with a warning. Empty or missing means nobody is eligible.
- In each group, only exact `email` rules and `email_domain` rules (that exact domain, no subdomains) can make an address eligible. Every other include rule, including `everyone`, nested groups (never followed), email lists, identity provider groups, claims, country, IP, device posture, login method, service tokens and anything unknown or malformed, is ignored: it grants nothing and does not disable the group.
- A group with any `require` rule is not used. Every `exclude` rule must be an `email` or `email_domain` rule, or the group is not used. A matching exclude blocks the address for that group.
- The lookup fails closed. A group that cannot be read (non-2xx, unsuccessful response, invalid JSON, network error) is skipped and grants nothing; the remaining groups are still checked. If none admits the address, it is ineligible.
- Eligibility is read live from the Cloudflare API on each invitation request, after the response is sent: at most one API call per listed group, in order, stopping at the first group that admits the address. Nothing is stored, so a change to a group applies to the next request. The cost is bounded by the per-IP limit and the per-address cooldown.
- Being in a listed group only lets a person enroll a passkey. Each Access application's own policy still decides what that person can reach. Every Access application that offers this identity provider should admit people through one of the listed groups; otherwise a person allowed by that application but in no listed group sees the identity provider at login and never receives an invitation.
- The Worker’s runtime API token is read-only with exactly one permission: `Access: Organizations, Identity Providers, and Groups Read`. The write token is used only by `bun run provision`, from the deployer’s machine; it is never given to the Worker.
- Recovery revokes nothing when it is requested. The old passkeys, sessions and OAuth tokens are deleted by a database trigger in the same statement that stores the new passkey registered through the link. If that insert fails, nothing is revoked.
- Enrolled users are never removed for becoming ineligible. Access enforces each application’s policy at sign-in.
- Invitation email is transactional, includes HTML and plain-text bodies, and is sent through the native Cloudflare Email Service binding.
- Resident credentials and user verification are required. The WebAuthn verification result is checked explicitly for the UV flag.
- Sign-in is usernameless and opens the browser or operating system’s account chooser for discoverable passkeys.
- Passkeys are email-bound: they are labeled with the email the link was sent to instead of a generic “Primary passkey” name.
- Signed-in users may add, rename and remove their own passkeys. Adding or removing requires a passkey sign-in within five minutes, the last passkey cannot be removed, at most 10 are allowed, and each change emails the account owner. These checks guard Better Auth's own delete and update endpoints as well as registration.
- A daily cron trigger removes expired challenges, sessions, OAuth tokens, expired request cooldown rows, and users without a passkey whose invitation expired unused, was revoked, or was consumed more than 30 days ago.
- Dynamic OAuth client registration and user-managed OAuth client CRUD are disabled.
- Exactly one confidential OIDC client exists. It requires PKCE, skips consent, and supports only the authorization-code grant. `bun run provision` writes it to D1 and never prints its secret; D1 stores only a hash.
- OIDC ID tokens use RS256 because Cloudflare Access does not support Better Auth’s default Ed25519/OKP signing keys. The included migration removes incompatible legacy keys when upgrading an existing deployment so Better Auth can generate an RSA key.
- When `PUBLIC_ORIGIN` is set, the Worker serves only that origin, so passkeys, issuer, and invitation links cannot vary by request host.
- Invitation tokens live in the URL fragment (`/invite#<token>`) and are sent only in a request header, so they are not written to request logs. Query-string tokens are ignored. Legacy `/invite/<token>` links still work until they expire, and error logs redact that path.

## Limits and residual risks

- Control of the mailbox is control of the account. Anyone who can read the email can enroll, or recover and replace the passkeys.
- Recovery does not end Access sessions or tokens already issued. They run until they expire.
- A Cloudflare API outage or rate limit makes everyone ineligible until it recovers.
- A person in a listed group can get a link even if no Access application allows them. Access still blocks them at each application.
- The Worker does not check that Access applications and the listed groups agree; keeping them aligned is a configuration duty.
- Turnstile is optional; when off, abuse is bounded only by the per-IP limit and the per-address cooldown.
- The recovery trigger was verified in local D1 only.
- The Access identity provider API calls in the provision script are not yet verified against a live account.

D1 is the system of record. KV is not required for correctness and should not replace D1 for relational authentication state.
