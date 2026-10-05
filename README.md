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

<!-- Deploy to Cloudflare button disabled until the one-click flow is verified end to end:
[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/andesco/cloudflare-access-passkeys-kit)
-->

### Suggested Prompt

```text
Use the authenticated `cf` CLI and the Cloudflare API or MCP to deploy this repository as a passkey identity provider for Cloudflare Access:

https://github.com/andesco/cloudflare-access-passkeys-kit

Read the README completely and follow its Manual Deployment steps in order, including the prerequisites, security constraints, Cloudflare Access integration, and verification steps. Ask the user which email identity to invite before creating the first invitation.
```

### Manual Deployment (`cf` CLI)

Verified order of operations. Do not run `bun run deploy` first: with required secrets missing it fails, and the failed attempt can leave an empty Worker behind that blocks the name.

**1. Install and sign in**

```bash
git clone https://github.com/andesco/cloudflare-access-passkeys-kit.git
cd cloudflare-access-passkeys-kit
bun install
bunx cf auth login
```

**2. Collect the values** (the deploy needs all six secrets)

| Secret | Where it comes from |
| --- | --- |
| `BETTER_AUTH_SECRET` | `openssl rand -hex 32` |
| `ADMIN_TOKEN` | a different `openssl rand -hex 32` |
| `CLOUDFLARE_ACCOUNT_ID` | `bunx cf accounts list` (the `id` field) |
| `ACCESS_POLICY_ID` | `bunx cf zero-trust access policies list`: the `id` of an `allow` policy whose `include` rules are exact `email` selectors and that has no `require` rules |
| `CLOUDFLARE_API_TOKEN` | open the [account token template](https://dash.cloudflare.com/?to=/:account/api-tokens&permissionGroupKeys=%5B%7B%22key%22%3A%22access%22%2C%22type%22%3A%22read%22%7D%5D&name=Access%20Passkeys%20Kit%20policy%20read) (permission prefilled), confirm it lists only `Access: Apps and Policies → Read`, then **Continue to summary** and **Create Token** (the `cf` login cannot create tokens). Copy the value; it is shown once |
| `INVITATION_FROM` | a sender address on an onboarded Email Service domain, such as `auth@send.example.com` |

Onboard the sender domain if it is not already (it must be on a zone in your account):

```bash
bunx cf email-sending subdomains create --zone example.com --name send.example.com
```

**3. Write a secrets file outside the repository**

```bash
cat > ~/passkeys-kit-secrets.env <<EOF
BETTER_AUTH_SECRET=$(openssl rand -hex 32)
ADMIN_TOKEN=$(openssl rand -hex 32)
CLOUDFLARE_ACCOUNT_ID={account-id}
ACCESS_POLICY_ID={policy-id}
CLOUDFLARE_API_TOKEN={api-token}
INVITATION_FROM=auth@send.example.com
EOF
chmod 600 ~/passkeys-kit-secrets.env
```

Keep `ADMIN_TOKEN`; the CLI administration commands need it. Delete the file when you are done.

**4. Choose the name, domain and origin**

The committed config deploys a Worker named `cloudflare-access-passkeys-kit` on `*.workers.dev` with an empty `PUBLIC_ORIGIN`. For a real deployment, copy `cloudflare.local.example.ts` to `cloudflare.local.ts` and set your own `name`, `domains` and `vars.PUBLIC_ORIGIN` (see [Personal Configuration](#personal-configuration-cloudflarelocalts)), then add `--mode personal` to the `cf` commands below, or use the `*:local` scripts after step 6. Leave `database` out of `cloudflare.local.ts` for the first deploy; `cf` provisions D1 itself.

**5. First deploy, with the secrets**

```bash
bun run build:client
bunx cf deploy --secrets-file ~/passkeys-kit-secrets.env
```

This creates the Worker, provisions the D1 database (`cloudflare-access-passkeys-kit-db` by default), attaches the daily cron, and sets all six secrets.

**6. Apply the schema**

```bash
bunx cf d1 list   # copy the id of the new database
bunx cf d1 migrations apply {database-id}
```

Then put that ID in `cloudflare.local.ts` (`database.id`) so `bun run deploy:local` and `bun run migrate:local` work from now on. For the default config, `D1_DATABASE_ID={database-id} bun run deploy` also works for later deploys.

**7. Check it**

```bash
curl -i https://{your-worker-origin}/                              # 200, the sign-in page
curl -i https://{your-worker-origin}/.well-known/openid-configuration   # 200
curl -i -H "authorization: Bearer {admin-token}" https://{your-worker-origin}/__admin/v1/invitations   # 200
```

If `PUBLIC_ORIGIN` is set, requests to any other hostname (including `*.workers.dev`) return 404 by design; use the public origin.

Later changes to a single secret: `bunx cf workers secrets update {NAME} --worker {worker-name} --text '{value}'`. Each change creates a new production Worker version.

**Turnstile.** `TURNSTILE_ENABLED` defaults to `"true"`, and the invitation form then needs a Turnstile widget. Create one (dashboard → Turnstile) for your origin and set `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET_KEY` as secrets, or set `TURNSTILE_ENABLED` to `"false"` in `cloudflare.local.ts`. Without the keys, invitation requests from the sign-in page fail.

**Variables.** Set `APP_NAME` (shown on the sign-in and enrollment pages, passkey prompt and invitation email; defaults to “Cloudflare Access Passkeys Kit”) and `PUBLIC_ORIGIN` (the Worker’s public origin, such as `https://auth.example.com`) in `cloudflare.local.ts`. When `PUBLIC_ORIGIN` is set, the Worker uses it for the WebAuthn relying party, OIDC issuer and invitation links, and answers every other hostname with 404. When empty, the origin of each request is used. Changing it later invalidates registered passkeys.

Never commit the Cloudflare Access API token, the Turnstile secret or the secrets file. The Email Sending binding is intentionally unrestricted in the reusable template because each deployment chooses its own sender domain; the application always sends from `INVITATION_FROM`.

<!-- Dashboard "clone a public repository" flow not yet verified. It runs `bun run deploy`, which needs the secrets and D1 ID described above.
Workers & Pages → Create application → Continue with GitHub → Clone a public repository via Git URL: https://github.com/andesco/cloudflare-access-passkeys-kit
-->

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

### Managing passkeys

After signing in, a user can add more passkeys (up to 10), rename them, and remove them from the sign-in page. Adding or removing a passkey requires a passkey sign-in within the last five minutes; the page asks the user to confirm with a passkey and retries. The last remaining passkey cannot be removed, and every add or remove sends a notice to the account email. Lost-passkey recovery through the CLI is still needed when a user has no working passkey.

### Scheduled cleanup

A daily cron trigger (04:17 UTC) deletes expired passkey challenges, sessions, and OAuth tokens, and users whose invitation expired unused or was revoked at least 30 days ago and who never registered a passkey. Worker logs record each run as `cleanup complete`.

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

Invitation URLs (`/invite#<token>`) are credentials until consumed. The token sits in the URL fragment, which browsers never send to the server, so it does not appear in Worker or Cloudflare request logs; the page sends it in an `x-invitation-token` header. Links issued before this format (`/invite/<token>`) still work until they expire. CLI-created URLs should be sent over a secure channel and kept out of tickets, logs, and chat archives. Policy-authorized users can instead request an email from the sign-in page; repeated delivery is suppressed for ten minutes after Cloudflare accepts the message. If Cloudflare rejects a send synchronously, the unsent invitation is removed so the user can retry immediately.

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

The working `.dev.vars` file and the generated `.cloudflare/` directory are gitignored.

### Personal Configuration: `cloudflare.local.ts`

Keep the account-specific Worker name, custom domain, D1 database ID, sender restrictions, application name, and feature choices in `cloudflare.local.ts` (copy `cloudflare.local.example.ts`). That filename is gitignored so the committed `cloudflare.config.ts` remains reusable and ID-free. `cloudflare.config.ts` loads it only under `--mode personal`, which the `*:local` scripts pass.

Use the committed Bun scripts so every personal operation selects the local config consistently:

```bash
bun run check:local
bun run dev:local
bun run migrate:local
bun run deploy:local
```

### Verification

`bun run check` builds the browser client, verifies generated Worker binding types, type-checks TypeScript, and runs a `cf deploy` dry run. `bun test` runs the unit and integration tests against an in-memory SQLite database that stands in for D1, including a check that `migrations/` still satisfies the schema Better Auth expects. GitHub Actions runs both on every push and pull request.

`public/assets/client.js` is a build artifact and is gitignored; every `dev`, `check`, and `deploy` script regenerates it.

```bash
bun run check
bun run check:local # when cloudflare.local.ts exists
bun test
```

[access]: https://developers.cloudflare.com/cloudflare-one/access-controls/
[better-auth]: https://www.better-auth.com/
[d1]: https://developers.cloudflare.com/d1/
[email-service]: https://developers.cloudflare.com/email-service/
[workers]: https://developers.cloudflare.com/workers/
[wrangler]: https://developers.cloudflare.com/workers/wrangler/
