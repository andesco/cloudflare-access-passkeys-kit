# Cloudflare Access Passkeys Kit

**Cloudflare Access Passkeys Kit** is an invitation-gated, email-bound passkey identity provider for [Cloudflare&nbsp;Access][access]. It runs [Better&nbsp;Auth][better-auth] as a small OpenID Connect identity provider on [Cloudflare&nbsp;Workers][workers]. Authentication state is stored in [Cloudflare&nbsp;D1][d1], and eligible people receive email links through the built-in [Cloudflare Email Service][email-service] integration. There is no administrator and no admin API.

Cloudflare Access is the access-control layer. It continues to handle application policies, permitted email addresses, sessions, identity-provider selection, and any OTP or MFA requirements. The Worker reads the Access groups named in its `ACCESS_GROUP_IDS` variable, sends a link only when the submitted address matches one of them, and never reveals the result in its browser response. There is no separate administrator: whoever can configure and deploy the Worker chooses the groups, and whoever can edit those groups in Cloudflare decides who is on them.

> This is an independent community project. It is not an official Better Auth or Cloudflare project.

## Deploy to Cloudflare

### Prerequisites

- domain name using Cloudflare DNS and Cloudflare Access
- at least one Cloudflare Access group whose include rules list exact emails or email domains (see [Who is eligible](#who-is-eligible))
- a deployer API token for the provision step, with `D1: Edit` and `Access: Organizations, Identity Providers, and Groups Write`
- a read-only runtime API token with exactly one permission: `Access: Organizations, Identity Providers, and Groups Read`
- domain or subdomain onboarded to Cloudflare Email Service

<!-- Deploy to Cloudflare button disabled until the one-click flow is verified end to end:
[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/andesco/cloudflare-access-passkeys-kit)
-->

### Suggested Prompt

```text
Use the authenticated `cf` CLI and the Cloudflare API or MCP to deploy this repository as a passkey identity provider for Cloudflare Access:

https://github.com/andesco/cloudflare-access-passkeys-kit

Read the README completely and follow its Manual Deployment steps in order, including the prerequisites, security constraints, Cloudflare Access integration, and verification steps. Ask the user which Access groups should decide who may enroll.
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

**2. Collect the values** (the deploy needs all four secrets)

| Secret | Where it comes from |
| --- | --- |
| `BETTER_AUTH_SECRET` | `openssl rand -hex 32` |
| `CLOUDFLARE_ACCOUNT_ID` | `bunx cf accounts list` (the `id` field) |
| `CLOUDFLARE_API_TOKEN` | open [account API tokens](https://dash.cloudflare.com/?to=/:account/api-tokens), create a custom token with exactly one permission, `Access: Organizations, Identity Providers, and Groups → Read`, then **Continue to summary** and **Create Token** (the `cf` login cannot create tokens). Copy the value; it is shown once |
| `INVITATION_FROM` | a sender address on an onboarded Email Service domain, such as `auth@send.example.com` |

Onboard the sender domain if it is not already (it must be on a zone in your account):

```bash
bunx cf email-sending subdomains create --zone example.com --name send.example.com
```

**3. Write a secrets file outside the repository**

```bash
cat > ~/passkeys-kit-secrets.env <<EOF
BETTER_AUTH_SECRET=$(openssl rand -hex 32)
CLOUDFLARE_ACCOUNT_ID={account-id}
CLOUDFLARE_API_TOKEN={api-token}
INVITATION_FROM=auth@send.example.com
EOF
chmod 600 ~/passkeys-kit-secrets.env
```

Delete the file when you are done.

**4. Choose the name, domain and origin**

The committed config deploys a Worker named `cloudflare-access-passkeys-kit` on `*.workers.dev` with an empty `PUBLIC_ORIGIN`. For a real deployment, copy `cloudflare.local.example.ts` to `cloudflare.local.ts` and set your own `name`, `domains`, `vars.PUBLIC_ORIGIN` and `vars.ACCESS_GROUP_IDS` (see [Personal Configuration](#personal-configuration-cloudflarelocalts)), then add `--mode personal` to the `cf` commands below, or use the `*:local` scripts after step 6. Leave `database` out of `cloudflare.local.ts` for the first deploy; `cf` provisions D1 itself.

**5. First deploy, with the secrets**

```bash
bun run build:client
bunx cf deploy --secrets-file ~/passkeys-kit-secrets.env
```

This creates the Worker, provisions the D1 database (`cloudflare-access-passkeys-kit-db` by default), attaches the daily cron, and sets all four secrets.

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
```

If `PUBLIC_ORIGIN` is set, requests to any other hostname (including `*.workers.dev`) return 404 by design; use the public origin.

Later changes to a single secret: `bunx cf workers secrets update {NAME} --worker {worker-name} --text '{value}'`. Each change creates a new production Worker version.

**Turnstile.** `TURNSTILE_ENABLED` defaults to `"true"`, and the request form then needs a Turnstile widget. Create one (dashboard → Turnstile) for your origin and set `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET_KEY` as secrets, or set `TURNSTILE_ENABLED` to `"false"` in `cloudflare.local.ts`. Without the keys, requests from the sign-in page fail. When Turnstile is off, abuse is bounded only by the per-IP limit and the per-address cooldown.

**Variables.** Set `APP_NAME` (shown on the sign-in and enrollment pages, passkey prompt and invitation email; defaults to “Cloudflare Access Passkeys Kit”) and `PUBLIC_ORIGIN` (the Worker’s public origin, such as `https://auth.example.com`) in `cloudflare.local.ts`. When `PUBLIC_ORIGIN` is set, the Worker uses it for the WebAuthn relying party, OIDC issuer and invitation links, and answers every other hostname with 404. When empty, the origin of each request is used. Changing it later invalidates registered passkeys.

**`ACCESS_GROUP_IDS`.** The Access groups that decide who may enroll (see [Who is eligible](#who-is-eligible)). It is a plain variable, not a secret: up to 10 group ids separated by commas and/or spaces. The default is empty, and then nobody is eligible.

Never commit the Cloudflare API tokens, the Turnstile secret or the secrets file. The Email Sending binding is intentionally unrestricted in the reusable template because each deployment chooses its own sender domain; the application always sends from `INVITATION_FROM`.

<!-- Dashboard "clone a public repository" flow not yet verified. It runs `bun run deploy`, which needs the secrets and D1 ID described above.
Workers & Pages → Create application → Continue with GitHub → Clone a public repository via Git URL: https://github.com/andesco/cloudflare-access-passkeys-kit
-->

### Connect Cloudflare Access

Find the Zero Trust team name under Settings → Custom Pages → Team domain. Create a deployer API token with `D1: Edit` and `Access: Organizations, Identity Providers, and Groups Write`, then run:

```bash
D1_DATABASE_ID={database-id} \
CLOUDFLARE_ACCOUNT_ID={account-id} \
PUBLIC_ORIGIN=https://{your-worker-origin} \
CLOUDFLARE_PROVISION_API_TOKEN='{deployer-token}' \
bun run provision {cloudflare-team-name}
```

The script writes the one OIDC client to D1, creates an Access identity provider named `Passkeys` with the Worker's authorization, token and JWKS URLs, and stores the provider id in D1 (`setting`, key `access_idp_id`). It never calls the Worker and never prints the client secret. It prints the identity provider id and the callback URL. If a step fails after the client was written, it restores D1 and says so.

To replace the client secret, run the same command with `--rotate`. It updates the secret in D1 and in the Access identity provider.

Then, in Zero Trust, add the `Passkeys` identity provider to each Access application you want to protect, and set `ACCESS_GROUP_IDS` (see [Who is eligible](#who-is-eligible)).

The registered callback is:

```text
https://{cloudflare-team-name}.cloudflareaccess.com/cdn-cgi/access/callback
```

Endpoints, for reference (the script sets them for you): `/api/auth/oauth2/authorize`, `/api/auth/oauth2/token`, `/api/auth/jwks`, and discovery at `/.well-known/openid-configuration`. Scopes are `openid email profile`, the email claim is `email`, and PKCE is on.

Cloudflare Access policies continue to decide which identities may reach each protected application. This identity provider only authenticates a person with a passkey and supplies the resulting OIDC identity to Cloudflare Access.

### Who is eligible

Eligibility comes only from the Access groups named in `ACCESS_GROUP_IDS`. Being eligible lets a person receive a link and enroll a passkey; each Access application's own policy still decides what that person can reach.

**Find a group id.** In Zero Trust, open the Access group and copy its id from the page URL, or list the account's groups with `bunx cf zero-trust access rule-groups list` (or the API, `GET /accounts/{account-id}/access/groups`) and copy the `id` field. Ids are 32 hexadecimal digits, with or without the usual UUID hyphens. Entries that are not ids are ignored with a warning in the Worker log, and so are ids after the tenth.

**How a group is read.** For each listed group, in order, the Worker makes one Cloudflare API call to read that group and stops at the first group that admits the address. Nothing is stored, so a change to a group applies to the next request. A group that cannot be read (an API error, a missing group, a token without access) is skipped and the next one is checked; if none can be read, nobody is eligible. Within a group:

- An `email` rule matches that exact address. An `email_domain` rule matches addresses at exactly that domain, not its subdomains. Matching ignores case and surrounding spaces.
- Every other include rule is ignored: `everyone`, nested Access groups (they are not followed), email lists, identity provider groups, SAML or OIDC claims, country, IP, device posture, login or authentication method, service tokens, and anything unknown or malformed. Such a rule never makes anyone eligible and does not stop the group's email and domain rules from working.
- A matching `exclude` rule blocks the address for that group. Every exclude rule must be an `email` or `email_domain` rule; if any other kind is present, the Worker does not use the group at all.
- A group with any `require` rule is not used at all.

**Keep Access applications and groups aligned.** Every Access application that offers the `Passkeys` identity provider should admit people through one of the listed groups. Otherwise a person whom that application allows but who is in none of the listed groups sees the `Passkeys` option at login and never receives an invitation.

The cost is at most one Cloudflare API call per listed group for each accepted request, bounded by the per-IP limit and the per-address cooldown. The check runs after the response is sent.

### Self-service enrollment and recovery

On the sign-in page, a person enters an email address (`POST /api/invitations/request`). The response is always the same and never says whether the address is eligible. If it is, the Worker emails:

- an invitation link, if the person has no passkey yet (valid 7 days), or
- a recovery link, if the person already has a passkey (valid 1 day).

Each address can request once every 10 minutes (the key is an HMAC of the address with any `+tag` ignored). A per-IP rate limit applies too.

Requesting recovery revokes nothing. The old passkeys, sessions and OAuth tokens are removed only when the new passkey registered through the link is stored (a database trigger in `migrations/0005_self_service.sql`).

Enrolled people are never removed for becoming ineligible. Access enforces each application's policy at sign-in.

### Example: share a local preview

Use a named Cloudflare Tunnel and Cloudflare Access to share a local service with users who can sign in through the passkey provider. See [Protected local preview](examples/protected-cloudflare-tunnel/README.md).

### Passkey behavior

Registration creates an email-bound, discoverable passkey: the verified invitation email becomes its WebAuthn user name, display name, and Better Auth label. Sign-in is usernameless: the passkey button opens the browser or operating system’s account chooser without first requesting an email address. The page has one email field: it is used by the “Email me a link” button, and in browsers that support passkey autofill, focusing it also suggests a passkey.

The email is not embedded in the public key or exposed through JWKS, but the user’s passkey manager may display it for account identification.

### Managing passkeys

After signing in, a user can add more passkeys (up to 10), rename them, and remove them from the sign-in page. Adding or removing a passkey requires a passkey sign-in within the last five minutes; the page asks the user to confirm with a passkey and retries. The last remaining passkey cannot be removed, and every add or remove sends a notice to the account email. A person with no working passkey requests a recovery link from the sign-in page.

### Scheduled cleanup

A daily cron trigger (04:17 UTC) deletes expired passkey challenges, sessions, and OAuth tokens, expired request cooldown rows, and users without a passkey whose invitation expired unused or was revoked, or was consumed more than 30 days ago. Worker logs record each run as `cleanup complete`.

## Responsibility Boundary

**Cloudflare Access Passkeys Kit**

- Passkey registration and verification
- Group-backed, self-service identity creation
- Transactional invitation delivery
- OIDC authorization, tokens, claims, and JWKS
- Passkey recovery by emailed link
- D1 persistence for the passkey identity provider

**Cloudflare Access**

- Protected application policies
- Permitted emails, domains, and groups (the Worker also reads the groups in `ACCESS_GROUP_IDS` to decide who may enroll)
- Final policy evaluation for authenticated requests
- OTP and identity-provider selection
- MFA requirements and application sessions
- Final allow/deny decision for each application

The project is deliberately not a general-purpose replacement for Cloudflare Access authentication features. Relevant future work is passkey-focused: stronger enrollment policy, authenticator metadata or attestation controls, additional claims for Cloudflare Access policy evaluation, and improved recovery operations.

## Security Profile

Passkeys are the only interactive sign-in method, enrollment and recovery use emailed links and depend on the Access groups named in `ACCESS_GROUP_IDS`, and there is no separate administrator. D1 is the system of record. See the [security model](docs/security-model.md) for the complete controls, trust boundaries, and signing-key details.

## Invitation links and delivery

Links (`/invite#<token>`) are credentials until used. The token sits in the URL fragment, which browsers never send to the server, so it does not appear in Worker or Cloudflare request logs; the page sends it in an `x-invitation-token` header. Links issued before this format (`/invite/<token>`) still work until they expire. If Cloudflare rejects a send synchronously, the unsent link is removed so the person can retry at once (the address cooldown is not released).

To diagnose delivery, stream Worker logs while requesting a link:

```bash
bunx wrangler tail
```

An accepted send logs the invitation ID and Cloudflare Email Sending message ID without logging the recipient or the link. Check the Email Sending suppression list and recipient spam or junk folder when Cloudflare accepts a message but it does not arrive.

## Upgrading from 1.x (breaking)

Version 2.0.0 is a breaking change. After upgrading, the admin CLI and admin API no longer exist, and nobody can get an invitation until `ACCESS_GROUP_IDS` is set and the token permission is replaced. See [CHANGELOG.md](CHANGELOG.md) for the full list.

- Delete the `ADMIN_TOKEN` and `ACCESS_POLICY_ID` secrets; they are no longer used. The Turnstile secrets and `TURNSTILE_ENABLED` are unchanged.
- Add `ACCESS_GROUP_IDS` (in `cloudflare.local.ts` under `vars`, or as a plain Worker variable) with the Access groups that should decide who may enroll. Until it is set, nobody is eligible.
- Replace the runtime `CLOUDFLARE_API_TOKEN` with a token that has exactly one permission, `Access: Organizations, Identity Providers, and Groups Read`. `Access: Apps and Policies Read` is no longer needed.
- Apply migrations 0004 and 0005 (`bun run migrate`, or `bun run deploy`).
- To use `bun run provision {team} --rotate` later, store the existing Access identity provider id in D1. `bun run provision` cannot adopt an existing provider: it only updates a provider whose id is already stored, and otherwise creates a new one. Either insert the id yourself, for example in the D1 console: `INSERT INTO setting (key, value) VALUES ('access_idp_id', '{idp-id}') ON CONFLICT(key) DO UPDATE SET value = excluded.value`, or run `bun run provision {team} --rotate`, which rotates the client secret and creates a new `Passkeys` identity provider (then switch your Access applications to it and delete the old one). Eligibility does not use this id.

## Local Development

```bash
bun install
cp .dev.vars.example .dev.vars
bun run dev
```

Eligibility reads the real Access groups in `ACCESS_GROUP_IDS` through `CLOUDFLARE_API_TOKEN` in `.dev.vars` (see [Who is eligible](#who-is-eligible)). `bun test` needs no Cloudflare account.

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
