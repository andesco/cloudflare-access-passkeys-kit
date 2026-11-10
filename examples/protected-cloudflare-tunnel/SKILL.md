---
name: protected-cloudflare-tunnel
description: Create, start, stop, or inspect a reusable named Cloudflare Tunnel protected by Cloudflare Access, with the Passkeys Kit OIDC provider available for sign-in. Use for sharing a local service, not temporary Quick Tunnels.
---

# Protected Cloudflare Tunnel

Set up a named Cloudflare Tunnel and Access application once, then reuse that same tunnel and hostname to share a local service. The Passkeys Kit provides OIDC sign-in; Access evaluates the policy and the tunnel connects to the local service. Preserve other desired sign-in methods.

## Remember the setup

Store non-secret configuration in `~/.config/protected-cloudflare-tunnel/<name>.json` with restrictive permissions. Record the user's chosen tunnel name, account ID, tunnel ID, hostname, zone ID, Access application ID, and policy ID. Record the last local port as a convenience, not as a default to expose without checking. Never store tokens, client secrets, invitation links, or other credentials there. Use a safe filename derived from the tunnel name. Track only connector processes started by this skill in a separate state file; validate process identity before stopping one.

On later requests, read the saved configuration and verify the live Cloudflare resources and their associations before acting. Select the named setup the user requested; if several match and the choice is unclear, ask. If nothing is saved, discover an existing setup or perform first-time setup. A changed hostname, account, or tunnel ID must not silently create or replace another resource.

## First-time setup

1. Verify `cf` is authenticated and `cloudflared` is available. Identify the account that owns the hostname, the desired tunnel name and hostname, the intended local port, and who may access it. Inspect existing applications, DNS records, tunnels, and policies before making changes. Ask for choices that cannot be inferred.
2. Check for the Passkeys Kit OIDC provider in the account with `cf zero-trust identity-providers list`. If it is missing, direct the user to https://github.com/andesco/cloudflare-access-passkeys-kit and help deploy and connect it when requested. Follow that repository's current deployment instructions and prerequisites; do not claim passkey sign-in is ready until the OIDC provider is connected and a permitted user is enrolled. Preserve other sign-in methods the user wants.
3. Find a suitable Access allow policy with `cf zero-trust access policies list`, or create one for the identities the user selected. Confirm its actual rules and audience. Create or verify the self-hosted Access application and attach the policy **before** publishing DNS. Ensure the Passkeys Kit provider is available and retain the other intended providers.
4. Create or reuse a remotely managed named tunnel. For a new tunnel, `cf tunnels create --name <name> --config-src cloudflare` creates it; capture its ID without exposing secrets. Configure an ingress rule mapping the hostname to `http://localhost:<port>`, followed by a 404 catch-all. `cf tunnels config update` replaces the configuration: read and preserve existing rules if reusing a tunnel.
5. Create or verify a proxied CNAME pointing the hostname to `<tunnel-id>.cfargotunnel.com`. Do not silently replace an existing record. Verify the unauthenticated Access redirect and the actual policy before exposing a service. Save the non-secret configuration for subsequent use. Discover syntax using `cf cli search`, command help, or `cf schema`; keep discovery queries free of identifying information.

## Start, inspect, and stop

For a start request, load the named setup and verify the Access application, policy, DNS mapping, tunnel ID, and ingress. Determine the requested port from the user's request or local context; if multiple servers could be intended, ask. Confirm the local server is listening before starting. If changing the port, preserve other ingress rules and update only the intended hostname. Never assume the previously saved port is still the intended service.

Fetch the token without printing it, and start the connector for the saved tunnel. The bundled `scripts/tunnel-preview.sh <port>` checks the loopback listener and runs an already-configured connector in the foreground using `TUNNEL_TOKEN` from its environment; it does not configure Cloudflare. If background operation is needed, record and verify the specific process this skill started. If a suitable connector is already running, reuse it rather than starting duplicates.

Check the Access redirect, tunnel connection, and local listener. When an authorized session is available, sign in through the passkey provider and confirm the preview loads; report any test that could not be completed. If the Access gate fails, stop the connector started for this task and correct the configuration before sharing. Tell the user the hostname, local destination, intended audience, and that local processes can reach the server directly.

For status, inspect saved settings, current Cloudflare resources, connector health, and the Access gate. For stop, stop only the connector or server started and tracked by this skill; do not stop unrelated tunnels. Keep the named tunnel, DNS, Access application, and saved configuration for reuse. When cleanup is requested, identify the exact resources first and do not delete shared policies, identity providers, or unrelated tunnels. Never disclose tunnel tokens, OIDC secrets, or invitation links.
