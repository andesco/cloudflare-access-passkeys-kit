// Optional secrets, only needed when TURNSTILE_ENABLED is "true". They are not declared in
// cloudflare.config.ts because declared secrets must exist for a deploy to succeed.
interface Env {
  TURNSTILE_SITE_KEY?: string;
  TURNSTILE_SECRET_KEY?: string;
}
