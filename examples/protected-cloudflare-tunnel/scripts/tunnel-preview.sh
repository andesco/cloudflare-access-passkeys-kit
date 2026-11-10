#!/usr/bin/env bash
# Run an already-configured named Cloudflare Tunnel in the foreground.
set -euo pipefail
if [[ $# -ne 1 || ! "$1" =~ ^[0-9]+$ ]] || (( 10#$1 < 1 || 10#$1 > 65535 )); then
  printf 'Usage: TUNNEL_TOKEN=<token in environment> %s <local-port>\n' "${0##*/}" >&2
  exit 2
fi
command -v cloudflared >/dev/null || { printf 'cloudflared is required\n' >&2; exit 1; }
command -v nc >/dev/null || { printf 'nc is required\n' >&2; exit 1; }
[[ -n "${TUNNEL_TOKEN:-}" ]] || { printf 'Set TUNNEL_TOKEN in the environment first\n' >&2; exit 1; }
nc -z 127.0.0.1 "$1" || { printf 'Nothing is listening on 127.0.0.1:%s\n' "$1" >&2; exit 1; }
printf 'Starting the configured tunnel; stop it with Ctrl-C.\n' >&2
exec cloudflared tunnel run
