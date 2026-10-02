import { createAuth, type Auth } from "./auth";
import { handleAdmin } from "./admin-api";
import { ADMIN_BASE_PATH, appName, configuredOrigin } from "./constants";
import { handleInvitationRequest } from "./invitation-request";
import { invitationRegistrationComplete } from "./invitations";
import { redactPath } from "./redact";

function redirect(location: string): Response {
  return new Response(null, {
    status: 302,
    headers: { location, "cache-control": "no-store" },
  });
}

function notFound(): Response {
  return new Response("Not found", { status: 404 });
}

function securePage(response: Response, turnstileEnabled: boolean): Response {
  const headers = new Headers(response.headers);
  headers.set("cache-control", "no-store");
  headers.set(
    "content-security-policy",
    turnstileEnabled
      ? "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; connect-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
      : "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
  );
  headers.set("permissions-policy", "publickey-credentials-create=(self), publickey-credentials-get=(self)");
  headers.set("referrer-policy", "no-referrer");
  headers.set("x-content-type-options", "nosniff");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

async function pageAsset(request: Request, env: Env, pathname: string): Promise<Response> {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response("Method not allowed", {
      status: 405,
      headers: { allow: "GET, HEAD", "cache-control": "no-store" },
    });
  }
  const assetUrl = new URL(request.url);
  assetUrl.pathname = pathname;
  const asset = await env.ASSETS.fetch(new Request(assetUrl, {
    method: request.method,
    headers: request.headers,
  }));
  return securePage(asset, env.TURNSTILE_ENABLED === "true");
}

export default {
  async fetch(request, env, ctx): Promise<Response> {
    const url = new URL(request.url);
    // Build Better Auth only for routes that need it.
    let auth: Auth | undefined;
    const getAuth = (): Auth => (auth ??= createAuth(env, request));

    try {
      const origin = configuredOrigin(env);
      if (origin && url.origin !== origin) return notFound();
      if (url.pathname === "/health") return Response.json({ ok: true });
      if (url.pathname.endsWith(".html")) return notFound();
      if (url.pathname === "/") return await pageAsset(request, env, "/sign-in.html");
      if (url.pathname === "/sign-in") return redirect(`/${url.search}`);
      if (url.pathname === "/api/invitations/request") {
        return await handleInvitationRequest(request, env, getAuth, ctx);
      }
      if (url.pathname === "/api/config") {
        const turnstileEnabled = env.TURNSTILE_ENABLED === "true";
        return Response.json({
          appName: appName(env),
          turnstileEnabled,
          ...(turnstileEnabled ? { turnstileSiteKey: env.TURNSTILE_SITE_KEY } : {}),
        }, {
          headers: { "cache-control": "no-store" },
        });
      }
      if (url.pathname === "/api/invitations/status" && request.method === "GET") {
        const token = url.searchParams.get("token") ?? "";
        const complete = token.length <= 128 && await invitationRegistrationComplete(env.DB, token);
        return Response.json({ complete }, { headers: { "cache-control": "no-store" } });
      }
      if (url.pathname === "/consent") {
        return new Response("Consent is disabled for the trusted Cloudflare Access client.", {
          status: 403,
          headers: { "cache-control": "no-store" },
        });
      }
      if (url.pathname.startsWith("/invite/")) {
        const token = url.pathname.slice("/invite/".length);
        if (!token || token.includes("/")) return notFound();
        return await pageAsset(request, env, "/invite.html");
      }
      if (url.pathname.startsWith(ADMIN_BASE_PATH)) return await handleAdmin(request, env, getAuth);
      if (url.pathname === "/.well-known/openid-configuration") {
        return Response.json(await getAuth().api.getOpenIdConfig(), {
          headers: { "cache-control": "public, max-age=300" },
        });
      }
      if (
        url.pathname === "/.well-known/oauth-authorization-server" ||
        url.pathname === "/.well-known/oauth-authorization-server/api/auth"
      ) {
        return Response.json(await getAuth().api.getOAuthServerConfig(), {
          headers: { "cache-control": "public, max-age=300" },
        });
      }
      if (url.pathname.startsWith("/api/auth/") || url.pathname.startsWith("/.well-known/")) {
        return await getAuth().handler(request);
      }
      return await env.ASSETS.fetch(request);
    } catch (error) {
      const details = error instanceof Response
        ? { kind: "Response", status: error.status, body: await error.clone().text() }
        : error instanceof Error
          ? {
              kind: error.name,
              message: error.message,
              stack: error.stack,
              body: "body" in error ? error.body : undefined,
              status: "status" in error ? error.status : undefined,
              statusCode: "statusCode" in error ? error.statusCode : undefined,
            }
          : { kind: typeof error, value: String(error) };
      console.error(JSON.stringify({
        message: "request failed",
        path: redactPath(url.pathname),
        error: details,
      }));
      return Response.json({ error: "Internal server error" }, { status: 500 });
    }
  },
} satisfies ExportedHandler<Env>;
