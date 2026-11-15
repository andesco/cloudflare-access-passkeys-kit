# Plan: eligibility from configured Access groups, no runtime admin

Status: in progress. Nothing is committed or pushed.

## Verified Cloudflare API facts (OpenAPI schema + docs, no live calls)

- `GET /accounts/{account_id}/access/groups/{group_id}` returns one Access group: `id`, `name`, `include`, `exclude`, `require`. Rules use the same schema as policies, for example `{"email":{"email":"a@b.c"}}` and `{"email_domain":{"domain":"b.c"}}`. Group ids are UUIDs.
- include = OR, require = AND, exclude = NOT. Groups may nest other groups (`{"group":{"id":...}}`).
- `email_list` contents need the Gateway lists API; its read permission is unconfirmed, so `email_list` never matches.
- Token permission: `Access: Organizations, Identity Providers, and Groups Read` is enough to read groups. `Access: Apps and Policies Read` is not needed.

## Design

- **Configuration**: the plain Worker variable `ACCESS_GROUP_IDS` (not a secret; default empty) lists Access group ids separated by commas and/or whitespace. Entries are trimmed, lowercased and deduplicated; each must be 32 hex digits or a hyphenated UUID, otherwise it is ignored with a warning; at most 10 are used (the rest are ignored with a warning). Empty or missing means nobody is eligible.
- **Administrators**: whoever can configure and deploy the Worker chooses the groups; whoever can edit those groups in Cloudflare manages who is on them. There is no admin API.
- **Eligibility** (`isEmailEligible(env, email)` in `src/access-groups.ts`, never throws): for each configured id in order, fetch the group with `CLOUDFLARE_API_TOKEN` and return true at the first group that admits the address; later groups are not fetched. A group whose fetch fails (non-2xx, `success !== true`, bad JSON, thrown) is skipped and the others are still checked.
- **Group evaluation**: a group with a non-empty `require` is unusable. Every `exclude` rule must be a well-formed `email` or `email_domain` rule, otherwise the group is unusable; a matching exclude blocks the address. Only `email` and `email_domain` include rules can match; every other include rule (`everyone`, nested `group`, `email_list`, IdP groups, claims, geo, IP, posture, login/auth method, service tokens, unknown, malformed) is ignored: it never grants and does not disable the group. Nested groups are not followed. Matching: trimmed and lowercased; `email` exact; `email_domain` equals the part after the `@` (one leading `@` stripped from the rule, no subdomains); the input needs exactly one `@` with non-empty parts.
- **No cache**: at most one API call per listed group per accepted request, after the response is sent. Nothing is stored or memoised; group changes apply immediately. Cost is bounded by the per-IP limit and the per-address cooldown. There is no KV binding.
- **Convention**: every Access application offering this IdP should admit people through one of the listed groups; otherwise a person allowed by that application but in no listed group sees the IdP and never receives an invitation. Being in a group lets someone enroll a passkey; each application's policy still decides access.
- **Self-service**: one endpoint, `POST /api/invitations/request`, always the same 202. Cooldown claim, eligibility and email send run in `ctx.waitUntil`. The Worker sends an invitation (no passkey yet) or a recovery link (passkey exists). Recovery revokes old passkeys, sessions and OAuth tokens only when the new passkey registration is verified. The sign-in confirmation tells everyone to ask the person who manages access if no email arrives.
- **Cooldown**: D1 `request_cooldown(email_hash, last_request_at)`, HMAC-SHA256 of the normalized email keyed by `BETTER_AUTH_SECRET`, 10 minutes, claimed atomically for eligible and ineligible addresses alike.
- **Turnstile**: optional, `TURNSTILE_ENABLED` (default `"true"`) with `TURNSTILE_SITE_KEY` / `TURNSTILE_SECRET_KEY` secrets.
- **Deploy time**: `bun run provision <team>` (`scripts/provision-access.ts`) uses the deployer's own Cloudflare API token to write the OIDC client row to D1, create the Access IdP, and store the IdP id in D1 `setting` (`key = access_idp_id`) for `--rotate`. Eligibility does not read it. It never calls the Worker. Migrations stay on `cf d1 migrations apply`.
- **Removed**: `/__admin/v1`, `src/admin.ts`, `ADMIN_TOKEN`, `ACCESS_POLICY_ID`, `src/schema.ts`.
- **Unchanged**: enrolled users are never pruned for ineligibility; expired-invitation cleanup stays.

## Design changes during the work

- The eligibility cache was removed: every check reads Access live and nothing is stored.
- Turnstile, first planned for removal, was restored as an optional feature.
- Eligibility by IdP discovery (listing every Access application that offers this IdP, collecting their allow policies and expanding groups) was replaced by the Access groups configured in `ACCESS_GROUP_IDS`.

## Tasks

| # | Task | Files (exclusive) | Depends on | Model / effort |
|---|------|-------------------|------------|----------------|
| R1 | Verify Cloudflare API shapes | none | - | Sonnet / medium (done) |
| R2 | Code map, deploy and self-service design | none | - | Sonnet / medium (done) |
| T1 | Remove admin API, CLI, `ADMIN_TOKEN`, `ACCESS_POLICY_ID`, Turnstile wiring | `src/admin*.ts`, `src/schema*.ts`, `src/env.d.ts`, `src/index.ts`, `src/index.test.ts`, `src/constants.ts`, `cloudflare*.ts`, `wrangler.config.ts`, `package.json`, `.dev.vars.example`, CI | R2 | Sonnet / low |
| T2 | Eligibility evaluation (live, no cache; now configured groups) | `src/access-groups.ts`, its test, `migrations/0004_eligibility.sql` | R1 | Opus / medium |
| T3 | Self-service invitation and recovery, cooldown | `src/invitation-request.ts`, `src/invitations.ts`, `src/cleanup.ts`, their tests, `src/auth.ts`, `src/crypto.ts`, `src/mail.ts`, `src/test/helpers.ts`, `migrations/0005_self_service.sql` | R2 | Opus / medium |
| T4 | Provision script + guard test | `scripts/provision-access.ts`, `scripts/provision-access.test.ts` | R2 | Sonnet / medium |
| T5 | Front end: drop Turnstile, adjust copy | `src/web/client.ts`, `public/*.html` | R2 | Sonnet / low |
| T6 | Integration: `bun test`, `bun run check`, cross-file fixes | any | T1-T5 | Sonnet / medium |
| T7 | Security review of group evaluation and invite flow (read-only) | none | T6 | Opus / medium |
| T8 | README, `docs/security-model.md`, example docs | `README.md`, `docs/`, `examples/` | T7 | Sonnet / low |

T1-T5 run in parallel. Then T6, T7, fixes from T7 if any, and T8 last, so the docs describe the reviewed code.
