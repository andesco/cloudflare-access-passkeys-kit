# Cloudflare Access Passkeys Kit

**Cloudflare Access Passkeys Kit** is an invitation-gated, email-bound passkey identity provider for [Cloudflare&nbsp;Access][access]. It runs [Better&nbsp;Auth][better-auth] as a small OpenID Connect identity provider on [Cloudflare&nbsp;Workers][workers]. Authentication state is stored in [Cloudflare&nbsp;D1][d1], administration remains CLI-only, and authorized users receive email invitations through the built-in [Cloudflare Email Service][email-service] integration.

Cloudflare Access is the access-control layer. It continues to handle application policies, permitted email addresses, sessions, identity-provider selection, and any OTP or MFA requirements. The Worker reads one reusable Cloudflare Access policy containing exact email selectors, sends an invitation only when the submitted address is listed, and never reveals the result in its browser response.

> This is an independent community project. It is not an official Better Auth or Cloudflare project.

## Deploy to Cloudflare

### Prerequisites

- domain name using Cloudflare DNS and Cloudflare Access
- Cloudflare Access `Allow` policy whose `Include` rules are exact `Email` selectors, with no `Require` rules or other selector types
- restricted API token with this Cloudflare Access permission: \
`Access: Apps and Policies Read`
- domain or subdomain onboarded to Cloudflare Email Service

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/andesco/cloudflare-access-passkeys-kit)

### Suggested Prompt

```text
Use authenticated Wrangler CLI and the Cloudflare API or MCP to deploy this repository as a passkey identity provider for Cloudflare Access:

https://github.com/andesco/cloudflare-access-passkeys-kit

Read the README completely and follow its Deploy to Cloudflare instructions, including the prerequisites, security constraints, Cloudflare Access integration, and verification steps. Ask the user which email identity to invite before creating the first invitation.
```

### Cloudflare Dashboard

Workers & Pages → [**Create application**](https://dash.cloudflare.com/?to=/:account/workers-and-pages/create/deploy-to-workers): Continue with GitHub: Clone a public repository via Git URL:

```text
https://github.com/andesco/cloudflare-access-passkeys-kit
```

Cloudflare automatically provisions and binds D1 from the draft `DB` binding in `wrangler.jsonc`. The deploy script applies the included schema migration immediately after the Worker is created; do not create a database manually or add an account-specific database ID to the repository.

During setup, provide two different high-entropy secrets:

- `BETTER_AUTH_SECRET`: signs Better Auth cookies and tokens.
- `ADMIN_TOKEN`: authenticates the Bun administration CLI.

Generate each value independently with `openssl rand -hex 32`.

These deployment-specific values are requested as bindings: `CLOUDFLARE_ACCOUNT_ID`, `ACCESS_POLICY_ID`, `CLOUDFLARE_API_TOKEN`, and `INVITATION_FROM`. `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET_KEY` are required only when `TURNSTILE_ENABLED` is `"true"`.

Set the non-secret `APP_NAME` variable to the user-facing application name shown on the sign-in and enrollment pages, passkey prompt, and invitation email. It defaults to “Cloudflare Access Passkeys Kit”.

Set the non-secret `PUBLIC_ORIGIN` variable to the Worker’s public origin, such as `https://auth.example.com`. When set, the Worker uses it for the WebAuthn relying party, OIDC issuer, and invitation links, and answers every other hostname (including `*.workers.dev`, and so the admin channel on it) with 404. When empty, the origin of each request is used.

### Wrangler CLI

```bash
git clone https://github.com/andesco/cloudflare-access-passkeys-kit.git
cd cloudflare-access-passkeys-kit
bun install
bunx wrangler whoami
bun run deploy
bunx wrangler secret put BETTER_AUTH_SECRET
bunx wrangler secret put ADMIN_TOKEN
```

The first deploy creates the Worker, automatically provisions D1, and then applies `migrations/0001_initial.sql`. Adding each secret creates a new production Worker version.

Onboard the sender domain before invitations are requested:

```bash
bunx wrangler email sending enable send.example.com
```

Set the enrollment bindings with `wrangler secret put`, or use one JSON object over standard input with `wrangler secret bulk`. Never commit the Cloudflare Access API token or Turnstile secret. The Email Sending binding is intentionally unrestricted in the reusable template because each deployment chooses its own sender domain; the application always sends from `INVITATION_FROM`.

### Connect Cloudflare Access

Find the Zero Trust team name under Settings → Custom Pages → Team domain, then provision the one OIDC client:

```bash
AUTH_ADMIN_URL=https://{your-worker-origin} \
AUTH_ADMIN_TOKEN='{your-admin-token}' \
bun run admin client provision {cloudflare-team-name}
```

Save the returned client secret immediately; Better Auth stores only its hash.

In Zero Trust, go to Integrations → Identity providers → Add new identity provider → OpenID Connect. Use the returned client ID and secret.

Authorization URL:

```text
https://{your-worker-origin}/api/auth/oauth2/authorize
```

Token URL:

```text
https://{your-worker-origin}/api/auth/oauth2/token
```

Certificate/JWKS URL:

```text
https://{your-worker-origin}/api/auth/jwks
```

Discovery URL:

```text
https://{your-worker-origin}/.well-known/openid-configuration
```

Scopes: `openid email profile`

Email claim: `email`

PKCE: Enabled

Registered callback:

```text
https://{cloudflare-team-name}.cloudflareaccess.com/cdn-cgi/access/callback
```

Cloudflare Access policies continue to decide which emails and identities may reach each protected application. This identity provider only authenticates an invited user with a passkey and supplies the resulting OIDC identity to Cloudflare Access.

### Passkey behavior

Registration creates an email-bound, discoverable passkey: the verified invitation email becomes its WebAuthn user name, display name, and Better Auth label. Sign-in is usernameless: the passkey button opens the browser or operating system’s account chooser without first requesting an email address. The page’s email field belongs only to the separate invitation form.

The email is not embedded in the public key or exposed through JWKS, but the user’s passkey manager may display it for account identification.

## Responsibility Boundary

**Cloudflare Access Passkeys Kit**

- Passkey registration and verification
- Policy-backed, invitation-gated identity creation
- Transactional invitation delivery
- OIDC authorization, tokens, claims, and JWKS
- Passkey/session recovery through the CLI
- D1 persistence for the passkey identity provider

**Cloudflare Access**

- Protected application policies
- Permitted emails, domains, and groups
- Final policy evaluation for authenticated requests
- OTP and identity-provider selection
- MFA requirements and application sessions
- Final allow/deny decision for each application

The project is deliberately not a general-purpose replacement for Cloudflare Access authentication features. Relevant future work is passkey-focused: stronger enrollment policy, authenticator metadata or attestation controls, additional claims for Cloudflare Access policy evaluation, improved recovery operations, and better CLI ergonomics.

## Security Profile

Passkeys are the only interactive sign-in method, enrollment is invitation-gated and backed by an exact-email Cloudflare Access policy, and administration and recovery remain CLI-only. D1 is the system of record. See the [security model](docs/security-model.md) for the complete controls, trust boundaries, and signing-key details.

## CLI Administration

All production commands require `AUTH_ADMIN_URL` and `AUTH_ADMIN_TOKEN`. The CLI communicates with a narrow authenticated command channel under `/__admin/v1`; “CLI-only” means the project exposes no browser administration interface.

```bash
# Apply or reconcile the schema
bun run admin migrate

# Create a seven-day invitation
bun run admin invite create person@example.com

# Create a shorter invitation
bun run admin invite create person@example.com --days 2

# List and revoke invitations
bun run admin invite list
bun run admin invite revoke {invitation-id}

# Lost-passkey recovery; revokes every passkey, session, and OAuth token first
bun run admin user recover person@example.com --days 1

# Provision and inspect the sole OIDC client
bun run admin client provision {cloudflare-team-name}
bun run admin client show
```

Invitation URLs are credentials until consumed. CLI-created URLs should be sent over a secure channel and kept out of tickets, logs, and chat archives. Policy-authorized users can instead request an email from the sign-in page; repeated delivery is suppressed for ten minutes after Cloudflare accepts the message. If Cloudflare rejects a send synchronously, the unsent invitation is removed so the user can retry immediately.

To diagnose delivery, stream Worker logs while requesting an invitation:

```bash
bunx wrangler tail
```

An accepted send logs the invitation ID and Cloudflare Email Sending message ID without logging the recipient or invitation URL. Check the Email Sending suppression list and recipient spam or junk folder when Cloudflare accepts a message but it does not arrive.

## Local Development

```bash
bun install
cp .dev.vars.example .dev.vars
bun run dev
```

In another shell:

```bash
AUTH_ADMIN_URL=http://localhost:8787 \
AUTH_ADMIN_TOKEN=your-local-admin-token \
bun run admin migrate
```

The working `.dev.vars` file and Wrangler state are gitignored.

### Personal Configuration: `wrangler.local.jsonc`

Keep account-specific resource IDs, routes, sender restrictions, application name, and feature choices in `wrangler.local.jsonc`. That filename is gitignored so the committed `wrangler.jsonc` remains reusable and ID-free. Wrangler config files do not inherit from `wrangler.jsonc`, so repeat `APP_NAME` in the personal config; it controls the invitation sender display name as well as the UI. This repository’s personal config disables Turnstile and binds the existing production D1 database explicitly.

Use the committed Bun scripts so every personal operation selects the local config consistently:

```bash
bun run check:local
bun run dev:local
bun run migrate:local
bun run deploy:local
```

### Verification

`bun run check` builds the browser client, verifies generated Worker binding types, type-checks TypeScript, and runs a Wrangler deployment dry run. `bun test` runs the unit and integration tests against an in-memory SQLite database that stands in for D1, including a check that `migrations/` still satisfies the schema Better Auth expects. GitHub Actions runs both on every push and pull request.

`public/assets/client.js` is a build artifact and is gitignored; every `dev`, `check`, and `deploy` script regenerates it.

```bash
bun run check
bun run check:local # when wrangler.local.jsonc exists
bun test
```

[access]: https://developers.cloudflare.com/cloudflare-one/access-controls/
[better-auth]: https://www.better-auth.com/
[d1]: https://developers.cloudflare.com/d1/
[email-service]: https://developers.cloudflare.com/email-service/
[workers]: https://developers.cloudflare.com/workers/
[wrangler]: https://developers.cloudflare.com/workers/wrangler/
