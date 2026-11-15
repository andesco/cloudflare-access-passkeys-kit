/**
 * Deploy-time provisioning of the single OIDC client and the matching Cloudflare Access identity provider.
 *
 *   bun run provision <team-name> [--rotate]
 *
 * Needs no Worker runtime credential and never calls the Worker. It talks only to the Cloudflare API,
 * using the deployer's own short-lived token (CLOUDFLARE_PROVISION_API_TOKEN) with "D1: Edit" and
 * "Access: Organizations, Identity Providers, and Groups Write".
 */
import { AUTH_BASE_PATH } from "../src/constants";

const API = "https://api.cloudflare.com/client/v4";
const ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const SCOPES = ["openid", "email", "profile"];
const IDP_SETTING_KEY = "access_idp_id";

export type Fetch = (input: string, init?: RequestInit) => Promise<Response>;
export type Sql = { sql: string; params: unknown[] };

export type ProvisionEnv = {
  accountId: string;
  databaseId: string;
  origin: string;
  token: string;
};

export class ProvisionError extends Error {}

export function validateTeam(team: string): string {
  if (!/^[a-z0-9-]+$/u.test(team) || team.length > 63 || team.startsWith("-") || team.endsWith("-")) {
    throw new ProvisionError("Team name must be lowercase letters, digits and hyphens (for example: my-team).");
  }
  return team;
}

export function validateOrigin(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ProvisionError("PUBLIC_ORIGIN must be a valid https origin.");
  }
  if (url.protocol !== "https:" || url.username || url.password) {
    throw new ProvisionError("PUBLIC_ORIGIN must be an https origin without credentials.");
  }
  return url.origin;
}

export function redirectUriFor(team: string): string {
  return `https://${team}.cloudflareaccess.com/cdn-cgi/access/callback`;
}

/** Endpoints Better Auth serves: the issuer is `<origin><AUTH_BASE_PATH>`. */
export function oidcEndpoints(origin: string) {
  const issuer = `${origin}${AUTH_BASE_PATH}`;
  return {
    auth_url: `${issuer}/oauth2/authorize`,
    token_url: `${issuer}/oauth2/token`,
    certs_url: `${issuer}/jwks`,
  };
}

export function randomString(length: number): string {
  const out: string[] = [];
  const limit = 256 - (256 % ALPHABET.length);
  while (out.length < length) {
    for (const byte of crypto.getRandomValues(new Uint8Array(length * 2))) {
      if (byte < limit && out.length < length) out.push(ALPHABET[byte % ALPHABET.length]!);
    }
  }
  return out.join("");
}

/**
 * Better Auth's default `storeClientSecret: "hashed"` (this project does not override it): the stored value is
 * unpadded base64url of SHA-256 over the UTF-8 secret (`defaultHasher` in @better-auth/oauth-provider).
 */
export async function hashClientSecret(secret: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret)));
  let binary = "";
  for (const byte of digest) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

/**
 * The `oauthClient` row equivalent to `adminCreateOAuthClient` with: confidential web client,
 * client_secret_basic, authorization_code/code, PKCE required, skip consent, end-session enabled,
 * public subject type, scope "openid email profile". `referenceId` matches `clientReference` in src/auth.ts.
 */
export async function buildClientInsert(input: {
  id: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  now: Date;
}): Promise<Sql> {
  const now = input.now.toISOString();
  return {
    sql: `INSERT INTO "oauthClient"
      ("id", "clientId", "clientSecret", "disabled", "skipConsent", "enableEndSession", "subjectType", "scopes",
       "createdAt", "updatedAt", "name", "redirectUris", "tokenEndpointAuthMethod", "grantTypes",
       "responseTypes", "public", "type", "requirePKCE", "referenceId")
      VALUES (?1, ?2, ?3, 0, 1, 1, 'public', ?4, ?5, ?5, 'Cloudflare Access', ?6,
              'client_secret_basic', ?7, ?8, 0, 'web', 1, 'cloudflare-access')`,
    params: [
      input.id,
      input.clientId,
      await hashClientSecret(input.clientSecret),
      JSON.stringify(SCOPES),
      now,
      JSON.stringify([input.redirectUri]),
      JSON.stringify(["authorization_code"]),
      JSON.stringify(["code"]),
    ],
  };
}

type D1Result = { results: Record<string, unknown>[] };

type Api = {
  d1(sql: string, params?: unknown[]): Promise<D1Result>;
  d1Batch(statements: Sql[]): Promise<void>;
  access(method: string, path: string, body?: unknown): Promise<{ id?: string }>;
};

async function call(fetchImpl: Fetch, env: ProvisionEnv, method: string, path: string, body?: unknown) {
  let response: Response;
  try {
    response = await fetchImpl(`${API}${path}`, {
      method,
      headers: {
        authorization: `Bearer ${env.token}`,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ProvisionError(`${method} ${path.replace(env.accountId, "<account>")}: network error`);
  }
  const text = await response.text();
  let envelope: { success?: boolean; errors?: { code?: number; message?: string }[]; result?: unknown } = {};
  try {
    envelope = JSON.parse(text);
  } catch {
    // Non-JSON body: report only the status.
  }
  if (!response.ok || envelope.success === false) {
    const detail = (envelope.errors ?? []).map((error) => `${error.code ?? "?"}: ${error.message ?? ""}`).join("; ");
    throw new ProvisionError(
      `Cloudflare API ${method} ${path.replace(env.accountId, "<account>").replace(env.databaseId, "<db>")} failed (HTTP ${response.status})${detail ? `: ${detail}` : ""}`,
    );
  }
  return envelope.result;
}

function makeApi(fetchImpl: Fetch, env: ProvisionEnv): Api {
  const query = `/accounts/${env.accountId}/d1/database/${env.databaseId}/query`;
  return {
    async d1(sql, params = []) {
      const result = (await call(fetchImpl, env, "POST", query, { sql, params })) as D1Result[];
      return result[0] ?? { results: [] };
    },
    async d1Batch(statements) {
      await call(fetchImpl, env, "POST", query, { batch: statements });
    },
    async access(method, path, body) {
      return (await call(fetchImpl, env, method, `/accounts/${env.accountId}/access/${path}`, body)) as { id?: string };
    },
  };
}

function idpBody(team: string, origin: string, clientId: string, clientSecret: string) {
  return {
    name: "Passkeys",
    type: "oidc",
    config: {
      client_id: clientId,
      client_secret: clientSecret,
      ...oidcEndpoints(origin),
      scopes: SCOPES,
      email_claim_name: "email",
      pkce_enabled: true,
    },
  };
}

export async function provision(
  team: string,
  rotate: boolean,
  env: ProvisionEnv,
  fetchImpl: Fetch,
  log: (line: string) => void,
): Promise<void> {
  const api = makeApi(fetchImpl, env);
  const redirectUri = redirectUriFor(team);

  const existing = (await api.d1(`SELECT "clientId", "clientSecret" FROM "oauthClient" LIMIT 2`)).results;
  if (existing.length > 1) throw new ProvisionError("Invariant violated: multiple OAuth clients exist.");
  if (existing.length === 1 && !rotate) {
    throw new ProvisionError("An OAuth client already exists. Use --rotate to replace its secret.");
  }
  if (existing.length === 0 && rotate) {
    throw new ProvisionError("No OAuth client exists to rotate. Run without --rotate.");
  }

  let idpId: string | undefined;
  try {
    const row = (await api.d1(`SELECT "value" FROM "setting" WHERE "key" = ?1`, [IDP_SETTING_KEY])).results[0];
    idpId = typeof row?.value === "string" ? row.value : undefined;
  } catch (error) {
    throw new ProvisionError(`${(error as Error).message}\nRun the migrations first (bun run migrate), then retry.`);
  }

  const clientSecret = randomString(48);
  const clientId = rotate ? String(existing[0]!.clientId) : randomString(32);
  const previousHash = rotate ? String(existing[0]!.clientSecret) : "";

  // Step 1: write the client to D1.
  if (rotate) {
    await api.d1(`UPDATE "oauthClient" SET "clientSecret" = ?1, "updatedAt" = ?2 WHERE "clientId" = ?3`, [
      await hashClientSecret(clientSecret),
      new Date().toISOString(),
      clientId,
    ]);
  } else {
    const insert = await buildClientInsert({
      id: crypto.randomUUID(),
      clientId,
      clientSecret,
      redirectUri,
      now: new Date(),
    });
    await api.d1(insert.sql, insert.params);
  }

  const rollback = async (): Promise<string> => {
    try {
      if (rotate) {
        await api.d1(`UPDATE "oauthClient" SET "clientSecret" = ?1 WHERE "clientId" = ?2`, [previousHash, clientId]);
        return "The previous client secret was restored in D1.";
      }
      await api.d1(`DELETE FROM "oauthClient" WHERE "clientId" = ?1`, [clientId]);
      return "The new OAuth client row was removed from D1.";
    } catch {
      return rotate
        ? "ROLLBACK FAILED: D1 holds the new secret but Access still has the old one. Run `bun run provision <team> --rotate` again."
        : "ROLLBACK FAILED: an orphan OAuth client row remains in D1. Run `bun run provision <team> --rotate` to finish, or delete the oauthClient row.";
    }
  };

  // Step 2: create or update the Access identity provider.
  const body = idpBody(team, env.origin, clientId, clientSecret);
  let idp: { id?: string };
  try {
    idp = idpId
      ? await api.access("PUT", `identity_providers/${encodeURIComponent(idpId)}`, body)
      : await api.access("POST", "identity_providers", body);
    if (!idp?.id) throw new ProvisionError("Cloudflare returned no identity provider id.");
  } catch (error) {
    throw new ProvisionError(`${(error as Error).message}\n${await rollback()}`);
  }

  // Step 3: remember the IdP id.
  try {
    await api.d1(
      `INSERT INTO "setting" ("key", "value") VALUES (?1, ?2)
       ON CONFLICT("key") DO UPDATE SET "value" = excluded."value"`,
      [IDP_SETTING_KEY, idp.id],
    );
  } catch (error) {
    throw new ProvisionError(
      `${(error as Error).message}\nThe Access identity provider ${idp.id} exists but its id could not be stored in D1. ` +
        `Store it with: INSERT INTO setting (key, value) VALUES ('${IDP_SETTING_KEY}', '${idp.id}') ` +
        `ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
    );
  }
  log(rotate ? "Rotated the client secret and updated the Access identity provider." : "Provisioned the client and the Access identity provider.");
  log(`Access identity provider id: ${idp.id}`);
  log(`Redirect URI: ${redirectUri}`);
  log("Next steps:");
  log("  1. In Cloudflare Zero Trust, add this identity provider to the Access applications to protect.");
  log("  2. Manage who may enroll through the Allow policies on those applications.");
}

export function readEnv(source: Record<string, string | undefined>): ProvisionEnv {
  const need = (name: string): string => {
    const value = source[name]?.trim();
    if (!value) throw new ProvisionError(`${name} is required.`);
    return value;
  };
  return {
    accountId: need("CLOUDFLARE_ACCOUNT_ID"),
    databaseId: need("D1_DATABASE_ID"),
    origin: validateOrigin(need("PUBLIC_ORIGIN")),
    token: need("CLOUDFLARE_PROVISION_API_TOKEN"),
  };
}

export async function main(
  argv: string[],
  source: Record<string, string | undefined>,
  fetchImpl: Fetch = fetch,
  log: (line: string) => void = console.log,
): Promise<number> {
  try {
    const rotate = argv.includes("--rotate");
    const positional = argv.filter((arg) => !arg.startsWith("--"));
    const unknown = argv.filter((arg) => arg.startsWith("--") && arg !== "--rotate");
    if (positional.length !== 1 || unknown.length > 0) {
      throw new ProvisionError("Usage: bun run provision <team-name> [--rotate]");
    }
    await provision(validateTeam(positional[0]!), rotate, readEnv(source), fetchImpl, log);
    return 0;
  } catch (error) {
    console.error(error instanceof Error ? error.message : "Provisioning failed.");
    return 1;
  }
}

if (import.meta.main) process.exit(await main(process.argv.slice(2), process.env));
