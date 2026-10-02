export const DEFAULT_APP_NAME = "Cloudflare Access Passkeys Kit";
export const AUTH_BASE_PATH = "/api/auth";
export const ADMIN_BASE_PATH = "/__admin/v1";

export function appName(env: Env): string {
  return env.APP_NAME?.trim() || DEFAULT_APP_NAME;
}

/** The pinned public origin, or null when `PUBLIC_ORIGIN` is unset and the request origin is used. */
export function configuredOrigin(env: Env): string | null {
  const value = env.PUBLIC_ORIGIN?.trim();
  return value ? new URL(value).origin : null;
}

export function requestOrigin(env: Env, request: Request): string {
  return configuredOrigin(env) ?? new URL(request.url).origin;
}
