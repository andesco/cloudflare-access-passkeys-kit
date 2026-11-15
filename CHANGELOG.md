# Changelog

All notable changes to this project are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 2.0.0 - 2026-11-14
### Breaking
- The admin API (`/__admin/v1`), the admin CLI (`bun run admin`) and the `ADMIN_TOKEN` secret are removed. There is no runtime administrator credential.
- `ACCESS_POLICY_ID` is removed. Eligibility now comes from the Access groups listed in the new `ACCESS_GROUP_IDS` variable. Until it is set, nobody can get an invitation.
- The Worker's `CLOUDFLARE_API_TOKEN` needs a different permission: `Access: Organizations, Identity Providers, and Groups Read`. `Access: Apps and Policies Read` is no longer used.
- Invitations and passkey recovery are no longer created by an administrator. People request a link by email on the sign-in page.
- OIDC client provisioning moved from `bun run admin client provision` to `bun run provision <team-name>`, which uses the deployer's own `CLOUDFLARE_PROVISION_API_TOKEN`.
- Database migrations 0004 and 0005 must be applied.
- A failed Turnstile check now returns 403 instead of 202.

### Added
- Self-service invitation and passkey recovery by email, with one neutral response for every address.
- Email-domain rules, in addition to exact emails, make an address eligible.
- A per-address cooldown of 10 minutes on link requests.
- Recovery links: old passkeys, sessions and tokens are removed only when the new passkey is stored.
- `scripts/provision-access.ts` (`bun run provision`, with `--rotate`).
- Passkey autofill on the sign-in email field: focusing it suggests a discoverable passkey in browsers that support conditional mediation.

### Changed
- Turnstile stays optional with the same default.
- One email field serves both actions on the sign-in page. "Sign in with passkey" does not need it, and "Email me a link" requires a valid address.
- Both sign-in buttons use the same neutral style.
- Cleanup also removes request cooldown records older than a day, and user rows that never got a passkey.

### Removed
- `src/admin-api.ts`, `src/admin.ts`, `src/access-policy.ts`, `src/schema.ts`.

## 1.0.0
- First version: eligibility from one reusable Access policy (`ACCESS_POLICY_ID`), administration through the admin CLI and `ADMIN_TOKEN`.
