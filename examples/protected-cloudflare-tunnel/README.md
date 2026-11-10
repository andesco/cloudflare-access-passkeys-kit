# Share a local preview with Cloudflare Access

Give invited users access to a server running on your computer through a stable hostname. They can sign in to Cloudflare Access using the passkey identity provider from this kit, alongside any other sign-in methods you choose to allow.

```text
Browser → Cloudflare Access → Cloudflare Tunnel → local server
                 ↓
         passkey OIDC provider
```

The passkeys kit authenticates the user; Access evaluates the application's policy; the tunnel connects Cloudflare to your local server. This example uses a **named tunnel**, not a temporary Quick Tunnel.

## Before you start

- Deploy the kit and [connect its OIDC provider to Access](../../README.md#connect-cloudflare-access). Invite and enroll at least one user whose email is permitted by the Access policy.
- Have a Cloudflare account, a domain in Cloudflare DNS, and a reusable Access allow policy for the people who should see the preview. Check who the policy includes before sharing.
- Install [cloudflared](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/downloads/) on the computer running the local server.
- Choose a hostname, such as `preview.example.com`, and a local port. This example uses `3000`.

## Option 1: Claude or Codex skill

The adjacent [SKILL.md](SKILL.md) is a shared agent skill that can guide Claude or Codex through this example using the `cf` CLI. From a clone of this repository, link the example folder into either assistant's skills directory:

```bash
mkdir -p ~/.agents/skills ~/.claude/skills
ln -s "$PWD/examples/protected-cloudflare-tunnel" ~/.agents/skills/protected-cloudflare-tunnel
ln -s "$PWD/examples/protected-cloudflare-tunnel" ~/.claude/skills/protected-cloudflare-tunnel
```

Run these commands from the repository root. If a destination already exists, inspect it before replacing it. Restart or refresh the assistant if the skill does not appear. The skill contains no account-specific settings or credentials.

## Option 2: Cloudflare Dashboard

### Create the Access application

1. Open the [Cloudflare Dashboard](https://dash.cloudflare.com/) and select the account that owns your domain. Go to **Zero Trust → Access controls → Applications**, then select **Create new application**.
2. Choose a self-hosted application. Give it a name such as `Local preview` and enter the public hostname, for example `preview.example.com`.
3. Under Access policies, add the existing reusable allow policy for the people who should see the preview. Review its audience.
4. Under authentication, make the passkeys kit's OIDC identity provider available along with any other sign-in methods you want to retain. Choose a session duration, review the application, and save it.

Follow Cloudflare's [self-hosted application guide](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/self-hosted-public-app/) if the Dashboard labels differ. Create and save this application **before** publishing the hostname.

### Create the tunnel and route

1. Start your local server on the chosen port, bound to loopback when possible.
2. In the Cloudflare Dashboard, go to **Networking → Tunnels**, select **Create a tunnel**, and name it, for example `local-preview`.
3. Choose your operating system and follow the Dashboard's instructions to install and connect `cloudflared` on the computer running the server. Wait for the tunnel to connect. The provided connector command contains a secret token: keep it private and do not commit or share it.
4. On the tunnel's **Routes** tab, select **Add route → Published application**. Enter `preview.example.com` as the hostname and `http://localhost:3000` as the service URL, substituting your own hostname and port. Select **Add route**. Cloudflare creates the corresponding DNS record.
5. Leave the local server and connector running. Check that the tunnel shows a healthy connection.

See Cloudflare's [dashboard tunnel guide](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/get-started/create-remote-tunnel/) for current Dashboard instructions.

## Option 3: `cf` CLI

Install the [Cloudflare `cf` CLI](https://github.com/cloudflare/cf), sign in with `cf auth login`, and install `jq`. Select the account that owns the hostname.

The commands below create new resources. Replace the example values with your own. Set `CLOUDFLARE_ACCOUNT_ID` to the account containing your domain and Access resources; list accounts with `cf accounts list`.

```bash
export CLOUDFLARE_ACCOUNT_ID="your-account-id"
export PREVIEW_HOST="preview.example.com"
export PREVIEW_ZONE="example.com"
export PREVIEW_PORT="3000"
export TUNNEL_NAME="local-preview"
```

### 1. Find the Access policy and identity provider

```bash
cf zero-trust access policies list
cf zero-trust identity-providers list
```

Choose the reusable allow policy for your intended audience and confirm the passkeys kit's OIDC provider appears. Note its policy ID below. The example allows the account's available identity providers, including the kit's provider and any other configured methods.

```bash
export PREVIEW_POLICY_ID="your-reusable-policy-id"
```

### 2. Create the Access application first

Create the application before publishing DNS so the hostname is protected when it becomes reachable. `allowed_idps: []` allows all available identity providers; confirm this matches your intended sign-in options.

```bash
cf zero-trust access applications create --body "$(jq -n \
  --arg host "$PREVIEW_HOST" --arg policy "$PREVIEW_POLICY_ID" \
  '{name: "Local preview", type: "self_hosted", domain: $host,
    session_duration: "24h", allowed_idps: [], auto_redirect_to_identity: false,
    policies: [{id: $policy, precedence: 1}]}')"
```

Check the returned application and policy before proceeding. If the hostname already has an application, inspect and reuse its configuration instead of creating a duplicate.

### 3. Create and route the tunnel

Create a remotely managed tunnel and copy its `id` from the output. If the name already exists, inspect the existing tunnel instead of creating another.

```bash
cf tunnels create --name "$TUNNEL_NAME" --config-src cloudflare | jq -r ".id"
export PREVIEW_TUNNEL_ID="the-returned-tunnel-id"
```

Configure the route, including a catch-all 404. This replaces the tunnel's ingress configuration, so use it only for the new example tunnel; inspect and preserve existing rules if reusing one.

```bash
cf tunnels config update "$PREVIEW_TUNNEL_ID" --body "$(jq -n \
  --arg host "$PREVIEW_HOST" --arg port "$PREVIEW_PORT" \
  '{config: {ingress: [{hostname: $host, service: ("http://localhost:" + $port)},
                       {service: "http_status:404"}]}}')"

cf dns records create --zone "$PREVIEW_ZONE" --body "$(jq -n \
  --arg host "$PREVIEW_HOST" --arg tunnel "$PREVIEW_TUNNEL_ID" \
  '{type: "CNAME", name: $host, content: ($tunnel + ".cfargotunnel.com"), proxied: true}')"
```

### 4. Run the connector

Start your local server on the chosen port, bound to loopback when possible. Fetch the connector token directly into the environment without printing it, then run the helper from this example's directory:

```bash
export TUNNEL_TOKEN="$(cf tunnels token get "$PREVIEW_TUNNEL_ID" | jq -r '.')"
./scripts/tunnel-preview.sh "$PREVIEW_PORT"
```

The helper checks the local listener and runs `cloudflared` in the foreground. Stop it with Ctrl-C and run `unset TUNNEL_TOKEN` when finished. Treat the tunnel token as a secret: do not print, commit, or share it. Keep the server and connector running while the preview is needed.

## Verify and share

Open the hostname in a private browser window. It should first show the Cloudflare Access sign-in page. Sign in with an invited passkey identity and check that the preview loads. Also verify that a person outside the allow policy cannot access it. If the sign-in page is missing or the wrong people can get in, stop the connector and review the application and policy before sharing the URL.

The local service is still accessible to software on your computer directly; Access protects requests that pass through Cloudflare. The preview goes offline when the local server, connector, or computer stops. When finished, stop the connector. Remove the published route, DNS record, Access application, and tunnel if you no longer need them; do not delete shared policies or identity providers used by other applications.
