import { beforeEach, describe, expect, test } from "bun:test";
import type { Database } from "bun:sqlite";
import { handleAdmin } from "./admin-api";
import { ADMIN_BASE_PATH } from "./constants";
import { migratedDatabase, ORIGIN, testAuth, testEnv } from "./test/helpers";

let sqlite: Database;
let env: Env;

function call(path: string, init: { method?: string; body?: unknown; token?: string | null } = {}) {
  const token = init.token === undefined ? env.ADMIN_TOKEN : init.token;
  const auth = testAuth(sqlite, env);
  return handleAdmin(
    new Request(`${ORIGIN}${ADMIN_BASE_PATH}${path}`, {
      method: init.method ?? "GET",
      headers: {
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...(init.body ? { "content-type": "application/json" } : {}),
      },
      body: init.body ? JSON.stringify(init.body) : undefined,
    }),
    env,
    () => auth,
  );
}

beforeEach(() => {
  sqlite = migratedDatabase();
  env = testEnv(sqlite);
});

describe("admin API", () => {
  test("rejects missing and wrong bearer tokens", async () => {
    expect((await call("/invitations", { token: null })).status).toBe(401);
    expect((await call("/invitations", { token: "wrong" })).status).toBe(401);
  });

  test("creates, lists and revokes an invitation", async () => {
    const created = await call("/invitations", {
      method: "POST",
      body: { email: "Person@Example.com", days: 2 },
    });
    expect(created.status).toBe(201);
    const body = await created.json() as { id: string; url: string; email: string };
    expect(body.email).toBe("person@example.com");
    expect(body.url.startsWith(`${ORIGIN}/invite/`)).toBe(true);

    const listed = await (await call("/invitations")).json() as { invitations: { id: string }[] };
    expect(listed.invitations.map((item) => item.id)).toEqual([body.id]);

    expect((await call(`/invitations/${body.id}`, { method: "DELETE" })).status).toBe(200);
    expect((await call(`/invitations/${body.id}`, { method: "DELETE" })).status).toBe(404);
    expect(sqlite.query("SELECT COUNT(*) AS n FROM user").get()).toEqual({ n: 0 });
  });

  test("validates the email and day count", async () => {
    expect((await call("/invitations", { method: "POST", body: { email: "nope" } })).status).toBe(400);
    expect((await call("/invitations", { method: "POST", body: { email: "a@b.co", days: 99 } })).status).toBe(400);
  });

  test("refuses to invite an existing user", async () => {
    await call("/invitations", { method: "POST", body: { email: "a@b.co" } });
    expect((await call("/invitations", { method: "POST", body: { email: "a@b.co" } })).status).toBe(409);
  });

  test("recovery revokes passkeys, sessions and OAuth tokens, then issues a new invitation", async () => {
    await call("/invitations", { method: "POST", body: { email: "a@b.co" } });
    const user = sqlite.query("SELECT id FROM user").get() as { id: string };
    const now = Date.now();
    sqlite.exec(`
      INSERT INTO passkey (id, publicKey, userId, credentialID, counter, deviceType, backedUp)
        VALUES ('p1', 'k', '${user.id}', 'c', 0, 'singleDevice', 0);
      INSERT INTO session (id, expiresAt, token, createdAt, updatedAt, userId)
        VALUES ('s1', ${now + 1e6}, 't', ${now}, ${now}, '${user.id}');
      INSERT INTO oauthClient (id, clientId, redirectUris) VALUES ('c1', 'client', '[]');
      INSERT INTO oauthAccessToken (id, token, clientId, sessionId, userId, expiresAt, createdAt, scopes)
        VALUES ('a1', 'at', 'client', 's1', '${user.id}', ${now + 1e6}, ${now}, 'openid');
      UPDATE invitation SET used_at = ${now};
    `);

    const response = await call("/users/recover", { method: "POST", body: { email: "a@b.co" } });
    expect(response.status).toBe(200);
    for (const table of ["passkey", "session", "oauthAccessToken"]) {
      expect(sqlite.query(`SELECT COUNT(*) AS n FROM ${table}`).get()).toEqual({ n: 0 });
    }
    expect(sqlite.query("SELECT used_at FROM invitation").get()).toEqual({ used_at: null });
    expect((await call("/users/recover", { method: "POST", body: { email: "x@y.co" } })).status).toBe(404);
  });
});
