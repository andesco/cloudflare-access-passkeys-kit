import { getMigrations } from "better-auth/db/migration";
import { makeSignature } from "better-auth/crypto";
import { ADMIN_BASE_PATH, requestOrigin } from "./constants";
import { randomToken, sha256Hex, timingSafeEqual } from "./crypto";
import { upsertInvitation } from "./invitations";
import { INVITATION_SCHEMA_STATEMENTS } from "./schema";
import { normalizeEmail } from "./validation";
import type { Auth } from "./auth";

const jsonHeaders = { "cache-control": "no-store" };

function json(data: unknown, status = 200): Response {
  return Response.json(data, { status, headers: jsonHeaders });
}

async function authorize(request: Request, expected: string): Promise<boolean> {
  const header = request.headers.get("authorization") ?? "";
  const prefix = "Bearer ";
  const provided = header.startsWith(prefix) ? header.slice(prefix.length) : "";
  return timingSafeEqual(provided, expected);
}

async function readJson(request: Request): Promise<Record<string, unknown>> {
  if (!request.headers.get("content-type")?.includes("application/json")) return {};
  const value: unknown = await request.json();
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

async function migrate(auth: Auth, db: D1Database): Promise<Response> {
  const migrations = await getMigrations(auth.options);
  await migrations.runMigrations();
  await db.batch(INVITATION_SCHEMA_STATEMENTS.map((statement) => db.prepare(statement)));
  return json({ ok: true });
}

async function createInvite(
  request: Request,
  env: Env,
  auth: Auth,
  db: D1Database,
): Promise<Response> {
  const body = await readJson(request);
  const email = normalizeEmail(body.email);
  const days = typeof body.days === "number" ? body.days : 7;
  if (!email) return json({ error: "A valid email is required" }, 400);
  if (!Number.isInteger(days) || days < 1 || days > 30) {
    return json({ error: "days must be an integer from 1 to 30" }, 400);
  }

  const context = await auth.$context;
  const existing = await context.internalAdapter.findUserByEmail(email, { includeAccounts: false });
  if (existing) return json({ error: "A user with this email already exists" }, 409);

  const token = randomToken();
  const user = await context.internalAdapter.createUser({
    email,
    name: email,
    emailVerified: true,
  });
  const invitation = {
    id: crypto.randomUUID(),
    tokenHash: await sha256Hex(token),
    expiresAt: Date.now() + days * 86_400_000,
    createdAt: Date.now(),
  };

  try {
    await db
      .prepare(
        `INSERT INTO invitation
          (id, token_hash, email, user_id, expires_at, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)`,
      )
      .bind(invitation.id, invitation.tokenHash, email, user.id, invitation.expiresAt, invitation.createdAt)
      .run();
  } catch (error) {
    await context.internalAdapter.deleteUser(user.id);
    throw error;
  }

  return json({
    id: invitation.id,
    email,
    expiresAt: new Date(invitation.expiresAt).toISOString(),
    url: `${requestOrigin(env, request)}/invite#${token}`,
  }, 201);
}

async function listInvites(db: D1Database): Promise<Response> {
  const result = await db
    .prepare(
      `SELECT id, email, user_id AS userId, expires_at AS expiresAt,
              used_at AS usedAt, revoked_at AS revokedAt, created_at AS createdAt
       FROM invitation ORDER BY created_at DESC LIMIT 100`,
    )
    .all();
  return json({ invitations: result.results });
}

async function revokeInvite(id: string, auth: Auth, db: D1Database): Promise<Response> {
  const revokedAt = Date.now();
  const result = await db
    .prepare(
      `UPDATE invitation SET revoked_at = ?1
       WHERE id = ?2 AND used_at IS NULL AND revoked_at IS NULL
       RETURNING user_id`,
    )
    .bind(revokedAt, id)
    .first<{ user_id: string }>();
  if (!result) return json({ error: "Active invitation not found" }, 404);

  const passkey = await db
    .prepare("SELECT id FROM passkey WHERE userId = ?1 LIMIT 1")
    .bind(result.user_id)
    .first<{ id: string }>();
  if (!passkey) {
    const context = await auth.$context;
    await context.internalAdapter.deleteUser(result.user_id);
  }
  return json({ ok: true });
}

async function recoverUser(
  request: Request,
  env: Env,
  auth: Auth,
  db: D1Database,
): Promise<Response> {
  const body = await readJson(request);
  const email = normalizeEmail(body.email);
  const days = typeof body.days === "number" ? body.days : 1;
  if (!email) return json({ error: "A valid email is required" }, 400);
  if (!Number.isInteger(days) || days < 1 || days > 7) {
    return json({ error: "days must be an integer from 1 to 7" }, 400);
  }

  const context = await auth.$context;
  const existing = await context.internalAdapter.findUserByEmail(email, { includeAccounts: false });
  if (!existing) return json({ error: "User not found" }, 404);

  const token = randomToken();
  const tokenHash = await sha256Hex(token);
  const now = Date.now();
  const expiresAt = now + days * 86_400_000;
  await db.batch([
    db.prepare("DELETE FROM oauthAccessToken WHERE userId = ?1").bind(existing.user.id),
    db.prepare("DELETE FROM oauthRefreshToken WHERE userId = ?1").bind(existing.user.id),
    db.prepare("DELETE FROM session WHERE userId = ?1").bind(existing.user.id),
    db.prepare("DELETE FROM passkey WHERE userId = ?1").bind(existing.user.id),
    upsertInvitation(db, {
      id: crypto.randomUUID(),
      tokenHash,
      email,
      userId: existing.user.id,
      expiresAt,
      createdAt: now,
    }),
  ]);

  return json({
    email,
    expiresAt: new Date(expiresAt).toISOString(),
    url: `${requestOrigin(env, request)}/invite#${token}`,
    warning: "All existing passkeys and sessions were revoked.",
  });
}

async function provisionClient(
  request: Request,
  env: Env,
  auth: Auth,
  db: D1Database,
): Promise<Response> {
  const body = await readJson(request);
  const teamName = typeof body.teamName === "string" ? body.teamName.trim().toLowerCase() : "";
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(teamName)) {
    return json({ error: "A valid Cloudflare Access team name is required" }, 400);
  }

  const count = await db.prepare("SELECT COUNT(*) AS count FROM oauthClient").first<{ count: number }>();
  if ((count?.count ?? 0) !== 0) {
    return json({ error: "The single OAuth client has already been provisioned" }, 409);
  }

  const redirectUri = `https://${teamName}.cloudflareaccess.com/cdn-cgi/access/callback`;
  const context = await auth.$context;
  const systemUser = await context.internalAdapter.createUser({
    email: `_system.${crypto.randomUUID()}@auth.invalid`,
    name: "OAuth client provisioner",
    emailVerified: true,
  });
  const session = await context.internalAdapter.createSession(systemUser.id);
  const sessionCookie = context.authCookies.sessionToken.name;
  const signedSession = `${session.token}.${await makeSignature(session.token, context.secret)}`;
  let client;
  try {
    client = await auth.api.adminCreateOAuthClient({
      headers: new Headers({ cookie: `${sessionCookie}=${signedSession}` }),
      body: {
        client_name: "Cloudflare Access",
        redirect_uris: [redirectUri],
        token_endpoint_auth_method: "client_secret_basic",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        type: "web",
        client_secret_expires_at: 0,
        skip_consent: true,
        enable_end_session: true,
        require_pkce: true,
        subject_type: "public",
        scope: "openid email profile",
      },
    });
  } finally {
    await context.internalAdapter.deleteUser(systemUser.id);
  }

  return json({
    client,
    cloudflareAccess: {
      redirectUri,
      discoveryUrl: `${requestOrigin(env, request)}/.well-known/openid-configuration`,
      pkceEnabled: true,
      scopes: ["openid", "email", "profile"],
      emailClaimName: "email",
    },
    warning: "The client secret is returned only now; store it securely.",
  }, 201);
}

async function showClient(db: D1Database): Promise<Response> {
  const client = await db
    .prepare(
      `SELECT clientId, name, redirectUris, scopes, disabled, requirePKCE, createdAt, updatedAt
       FROM oauthClient LIMIT 2`,
    )
    .all();
  if (client.results.length === 0) return json({ error: "No OAuth client is provisioned" }, 404);
  if (client.results.length > 1) return json({ error: "Invariant violated: multiple OAuth clients exist" }, 500);
  return json({ client: client.results[0] });
}

export async function handleAdmin(
  request: Request,
  env: Env,
  getAuth: () => Auth,
): Promise<Response> {
  if (!(await authorize(request, env.ADMIN_TOKEN))) {
    return json({ error: "Unauthorized" }, 401);
  }
  const auth = getAuth();

  const url = new URL(request.url);
  const path = url.pathname.slice(ADMIN_BASE_PATH.length);
  if (request.method === "POST" && path === "/migrate") return migrate(auth, env.DB);
  if (request.method === "POST" && path === "/invitations") {
    return createInvite(request, env, auth, env.DB);
  }
  if (request.method === "GET" && path === "/invitations") return listInvites(env.DB);
  if (request.method === "DELETE" && path.startsWith("/invitations/")) {
    return revokeInvite(decodeURIComponent(path.slice("/invitations/".length)), auth, env.DB);
  }
  if (request.method === "POST" && path === "/users/recover") {
    return recoverUser(request, env, auth, env.DB);
  }
  if (request.method === "POST" && path === "/client") {
    return provisionClient(request, env, auth, env.DB);
  }
  if (request.method === "GET" && path === "/client") return showClient(env.DB);
  return json({ error: "Not found" }, 404);
}
