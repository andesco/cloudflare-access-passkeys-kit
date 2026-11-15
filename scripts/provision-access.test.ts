import { beforeEach, describe, expect, mock, spyOn, test } from "bun:test";
import type { Database } from "bun:sqlite";
import { makeSignature } from "better-auth/crypto";
import { migratedDatabase, ORIGIN, signedInUser, testAuth, testEnv } from "../src/test/helpers";
import {
  buildClientInsert,
  hashClientSecret,
  main,
  oidcEndpoints,
  type Fetch,
} from "./provision-access";

const TEAM = "example-team";
const REDIRECT = `https://${TEAM}.cloudflareaccess.com/cdn-cgi/access/callback`;
const TOKEN = "provision-token-for-tests";
const SOURCE = {
  CLOUDFLARE_ACCOUNT_ID: "acct0123",
  D1_DATABASE_ID: "db0123",
  PUBLIC_ORIGIN: ORIGIN,
  CLOUDFLARE_PROVISION_API_TOKEN: TOKEN,
};

let sqlite: Database;
let requests: { method: string; path: string; body: any }[];
let idps: Map<string, any>;
let failAccess: boolean;
let output: string[];

/** Fake Cloudflare API: D1 queries run against the migrated in-memory SQLite, Access is an in-memory map. */
const fakeFetch: Fetch = async (input, init) => {
  const path = new URL(input).pathname.replace("/client/v4", "");
  const body = init?.body ? JSON.parse(String(init.body)) : undefined;
  requests.push({ method: init?.method ?? "GET", path, body });
  expect((init?.headers as Record<string, string>).authorization).toBe(`Bearer ${TOKEN}`);
  const ok = (result: unknown) => Response.json({ success: true, errors: [], result });
  if (path.endsWith("/query")) {
    const statements: { sql: string; params?: unknown[] }[] = body.batch ?? [body];
    try {
      const results = statements.map(({ sql, params = [] }) => {
        const statement = sqlite.prepare(sql);
        return { results: statement.all(...(params as never[])), success: true };
      });
      return ok(results);
    } catch (error) {
      return Response.json(
        { success: false, errors: [{ code: 7500, message: (error as Error).message }], result: null },
        { status: 400 },
      );
    }
  }
  if (path.includes("/access/identity_providers")) {
    if (failAccess) {
      return Response.json({ success: false, errors: [{ code: 10000, message: "denied" }], result: null }, { status: 403 });
    }
    if (init?.method === "POST") {
      const id = crypto.randomUUID();
      idps.set(id, body);
      return ok({ id, ...body });
    }
    const id = decodeURIComponent(path.split("/").pop()!);
    idps.set(id, body);
    return ok({ id, ...body });
  }
  return new Response("unexpected", { status: 500 });
};

function run(...args: string[]) {
  return main(args, SOURCE, fakeFetch, (line) => output.push(line));
}

function oauthClients() {
  return sqlite.query(`SELECT * FROM oauthClient`).all() as Record<string, any>[];
}

beforeEach(() => {
  sqlite = migratedDatabase();
  // Normally created by migration 0004; keep the script testable if that migration is not present.
  sqlite.exec(`CREATE TABLE IF NOT EXISTS setting (key TEXT PRIMARY KEY, value TEXT NOT NULL)`);
  requests = [];
  idps = new Map();
  failAccess = false;
  output = [];
});

describe("provision script", () => {
  test("provisions a client, creates the IdP and stores its id without leaking secrets", async () => {
    const stderr = spyOn(console, "error").mockImplementation(() => {});
    expect(await run(TEAM)).toBe(0);
    stderr.mockRestore();

    expect(oauthClients()).toHaveLength(1);
    const [idp] = [...idps.values()];
    expect(idp.type).toBe("oidc");
    expect(idp.config).toMatchObject({
      auth_url: `${ORIGIN}/api/auth/oauth2/authorize`,
      token_url: `${ORIGIN}/api/auth/oauth2/token`,
      certs_url: `${ORIGIN}/api/auth/jwks`,
      scopes: ["openid", "email", "profile"],
      email_claim_name: "email",
      pkce_enabled: true,
    });
    const idpId = [...idps.keys()][0]!;
    expect(sqlite.query(`SELECT value FROM setting WHERE key = 'access_idp_id'`).get()).toEqual({ value: idpId });
    expect(oauthClients()[0]!.clientId).toBe(idp.config.client_id);
    expect(oauthClients()[0]!.clientSecret).toBe(await hashClientSecret(idp.config.client_secret));

    const printed = output.join("\n");
    expect(printed).toContain(idpId);
    expect(printed).not.toContain(idp.config.client_secret);
    expect(printed).not.toContain(TOKEN);
  });

  test("every D1 statement is parameterised: no value is ever inlined into SQL", async () => {
    await run(TEAM);
    const idp = [...idps.values()][0];
    for (const request of requests.filter((item) => item.path.endsWith("/query"))) {
      for (const { sql } of request.body.batch ?? [request.body]) {
        expect(sql).not.toContain(idp.config.client_secret);
        expect(sql).not.toContain(idp.config.client_id);
        expect(sql).not.toContain(REDIRECT);
        expect(sql).not.toContain(TEAM);
      }
    }
  });

  test("refuses when a client exists unless --rotate, and --rotate needs an existing client", async () => {
    const stderr = spyOn(console, "error").mockImplementation(() => {});
    expect(await run("--rotate", TEAM)).toBe(1);
    expect(await run(TEAM)).toBe(0);
    expect(await run(TEAM)).toBe(1);
    expect(idps.size).toBe(1);
    stderr.mockRestore();
  });

  test("--rotate replaces the secret, keeps the client id and updates the stored IdP", async () => {
    await run(TEAM);
    const before = oauthClients()[0]!;
    const idpId = [...idps.keys()][0]!;
    const firstSecret = idps.get(idpId).config.client_secret;
    output = [];
    requests = [];

    expect(await run(TEAM, "--rotate")).toBe(0);
    const after = oauthClients()[0]!;
    expect(after.clientId).toBe(before.clientId);
    expect(after.clientSecret).not.toBe(before.clientSecret);
    expect(idps.size).toBe(1);
    const updated = idps.get(idpId);
    expect(updated.config.client_id).toBe(before.clientId);
    expect(updated.config.client_secret).not.toBe(firstSecret);
    expect(after.clientSecret).toBe(await hashClientSecret(updated.config.client_secret));
    expect(requests.some((item) => item.method === "PUT" && item.path.endsWith(`/identity_providers/${idpId}`))).toBe(true);
    expect(output.join("\n")).not.toContain(updated.config.client_secret);
  });

  test("rolls back the client row when creating the IdP fails", async () => {
    const stderr = spyOn(console, "error").mockImplementation(() => {});
    failAccess = true;
    expect(await run(TEAM)).toBe(1);
    expect(oauthClients()).toHaveLength(0);
    const message = String(stderr.mock.calls[stderr.mock.calls.length - 1]?.[0]);
    expect(message).toContain("removed");
    expect(message).not.toContain(TOKEN);
    stderr.mockRestore();
  });

  test("restores the old secret when updating the IdP fails during rotation", async () => {
    const stderr = spyOn(console, "error").mockImplementation(() => {});
    await run(TEAM);
    const before = oauthClients()[0]!;
    failAccess = true;
    expect(await run(TEAM, "--rotate")).toBe(1);
    expect(oauthClients()[0]!.clientSecret).toBe(before.clientSecret);
    stderr.mockRestore();
  });

  test("rejects bad input before any network call", async () => {
    const stderr = spyOn(console, "error").mockImplementation(() => {});
    expect(await run("Bad_Team")).toBe(1);
    expect(await run()).toBe(1);
    expect(await main([TEAM], { ...SOURCE, PUBLIC_ORIGIN: "http://insecure.test" }, fakeFetch, () => {})).toBe(1);
    expect(await main([TEAM], { ...SOURCE, CLOUDFLARE_PROVISION_API_TOKEN: "" }, fakeFetch, () => {})).toBe(1);
    expect(requests).toHaveLength(0);
    stderr.mockRestore();
  });
});

describe("guard: the real Better Auth library accepts the provisioned row", () => {
  test("row equals what adminCreateOAuthClient writes, apart from generated values", async () => {
    const reference = migratedDatabase();
    const env = testEnv(reference);
    // Production denies every client-management call (`clientPrivileges: () => false`), so the
    // reference auth instance is built from a copy of src/auth.ts whose oauthProvider grants it.
    const real = { ...(await import("@better-auth/oauth-provider")) };
    const realOauthProvider = real.oauthProvider;
    mock.module("@better-auth/oauth-provider", () => ({
      ...real,
      oauthProvider: (options: any) => realOauthProvider({ ...options, clientPrivileges: () => true, clientReference: () => "cloudflare-access" }),
    }));
    const { createAuth: createReferenceAuth } = await import(`../src/auth.ts?reference=${crypto.randomUUID()}`);
    const auth = createReferenceAuth(env, new Request(`${ORIGIN}/`), reference) as ReturnType<typeof testAuth>;
    const context = await auth.$context;
    const system = await context.internalAdapter.createUser({
      email: `_system.${crypto.randomUUID()}@auth.invalid`,
      name: "OAuth client provisioner",
      emailVerified: true,
    });
    const session = await context.internalAdapter.createSession(system.id);
    const signed = `${session.token}.${await makeSignature(session.token, context.secret)}`;
    await auth.api.adminCreateOAuthClient({
      headers: new Headers({ cookie: `${context.authCookies.sessionToken.name}=${signed}` }),
      body: {
        client_name: "Cloudflare Access",
        redirect_uris: [REDIRECT],
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
    const expected = reference.query(`SELECT * FROM oauthClient`).get() as Record<string, any>;

    const mine = migratedDatabase();
    const insert = await buildClientInsert({
      id: crypto.randomUUID(),
      clientId: "client-id",
      clientSecret: "client-secret",
      redirectUri: REDIRECT,
      now: new Date(),
    });
    mine.prepare(insert.sql).run(...(insert.params as never[]));
    const actual = mine.query(`SELECT * FROM oauthClient`).get() as Record<string, any>;

    // userId is the creating session's user in the reference; the provisioned client is deliberately ownerless.
    const generated = ["id", "clientId", "clientSecret", "createdAt", "updatedAt", "userId"];
    expect(actual.userId).toBeNull();
    for (const column of Object.keys(expected).filter((name) => !generated.includes(name))) {
      expect([column, actual[column]]).toEqual([column, expected[column]]);
    }
    // Same storage shape for the generated columns.
    expect(typeof actual.createdAt).toBe(typeof expected.createdAt);
    expect(String(actual.createdAt)).toMatch(/^\d{4}-\d{2}-\d{2}T/u);
    expect(String(expected.createdAt)).toMatch(/^\d{4}-\d{2}-\d{2}T/u);
    expect(actual.clientSecret).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(expected.clientSecret).toMatch(/^[A-Za-z0-9_-]{43}$/u);
  });

  test("full authorization-code + PKCE exchange with the provisioned client and secret", async () => {
    await run(TEAM);
    const idp = [...idps.values()][0];
    const { client_id: clientId, client_secret: clientSecret, auth_url: authUrl, token_url: tokenUrl } = idp.config;
    expect({ auth_url: authUrl, token_url: tokenUrl }).toMatchObject({
      auth_url: oidcEndpoints(ORIGIN).auth_url,
      token_url: oidcEndpoints(ORIGIN).token_url,
    });

    const env = testEnv(sqlite);
    const auth = testAuth(sqlite, env);
    const { headers } = await signedInUser(sqlite, auth);

    const verifier = "v".repeat(64);
    const challenge = Buffer.from(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
    ).toString("base64url");
    const authorizeCode = async () => {
      const authorize = new URL(authUrl);
      authorize.search = new URLSearchParams({
        response_type: "code",
        client_id: clientId,
        redirect_uri: REDIRECT,
        scope: "openid email profile",
        state: "s",
        code_challenge: challenge,
        code_challenge_method: "S256",
      }).toString();
      const authorized = await auth.handler(new Request(authorize, { headers }));
      const location = new URL(authorized.headers.get("location") ?? "", ORIGIN);
      expect(location.origin + location.pathname).toBe(new URL(REDIRECT).origin + new URL(REDIRECT).pathname);
      const value = location.searchParams.get("code");
      expect(value).toBeTruthy();
      return value!;
    };

    const exchange = (secret: string, codeValue: string) =>
      auth.handler(
        new Request(tokenUrl, {
          method: "POST",
          headers: {
            "content-type": "application/x-www-form-urlencoded",
            authorization: `Basic ${btoa(`${clientId}:${secret}`)}`,
          },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            code: codeValue,
            redirect_uri: REDIRECT,
            code_verifier: verifier,
          }),
        }),
      );

    // A wrong secret is rejected, so the check is real.
    expect((await exchange("wrong-secret", await authorizeCode())).status).toBe(401);

    const token = await exchange(clientSecret, await authorizeCode());
    expect(token.status).toBe(200);
    const payload = (await token.json()) as { id_token?: string; access_token?: string };
    expect(payload.id_token).toBeTruthy();
    const claims = JSON.parse(Buffer.from(payload.id_token!.split(".")[1]!, "base64url").toString());
    expect(claims.email).toBe("person@example.com");
    expect(claims.iss).toBe(`${ORIGIN}/api/auth`);
  });

  test("a rotated secret works and the previous one stops working", async () => {
    await run(TEAM);
    const first = [...idps.values()][0].config.client_secret as string;
    await run(TEAM, "--rotate");
    const second = [...idps.values()][0].config.client_secret as string;
    expect(second).not.toBe(first);
    const stored = (sqlite.query(`SELECT clientSecret FROM oauthClient`).get() as { clientSecret: string }).clientSecret;
    expect(stored).toBe(await hashClientSecret(second));
    expect(stored).not.toBe(await hashClientSecret(first));
  });
});
