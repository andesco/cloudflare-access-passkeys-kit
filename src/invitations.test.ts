import { beforeEach, describe, expect, test } from "bun:test";
import type { Database } from "bun:sqlite";
import { sha256Hex } from "./crypto";
import {
  INVITATION_HEADER,
  RECOVERY_DAYS,
  cancelUnsentInvitation,
  completeInvitation,
  consumeInvitation,
  invitationRegistrationComplete,
  issueInvitation,
  resolveInvitation,
} from "./invitations";
import { migratedDatabase, ORIGIN, signedInUser, testAuth, testEnv } from "./test/helpers";
import { registrationResponse } from "./test/webauthn";

let sqlite: Database;
let env: Env;
let auth: ReturnType<typeof testAuth>;

beforeEach(() => {
  sqlite = migratedDatabase();
  env = testEnv(sqlite);
  auth = testAuth(sqlite, env);
});

async function issue(email = "person@example.com") {
  return issueInvitation(env.DB, email);
}

function addPasskey(userId: string) {
  sqlite.exec(
    `INSERT INTO passkey (id, publicKey, userId, credentialID, counter, deviceType, backedUp)
     VALUES ('p1', 'key', '${userId}', 'cred', 0, 'singleDevice', 0)`,
  );
}

const registerWith = async (token: string | null, query: Record<string, string> = {}, cookie?: string) => {
  const headers = new Headers({ origin: ORIGIN });
  if (token) headers.set(INVITATION_HEADER, token);
  if (cookie) headers.set("cookie", cookie);
  const optionsResponse = await auth.api.generatePasskeyRegistrationOptions({ headers, query, asResponse: true });
  const options = await optionsResponse.json() as { challenge: string };
  const challengeCookies = optionsResponse.headers.getSetCookie().map((value) => value.split(";")[0]!);
  headers.set("cookie", [...(cookie ? [cookie] : []), ...challengeCookies].join("; "));
  const response = await registrationResponse({
    challenge: options.challenge,
    origin: ORIGIN,
    rpId: new URL(ORIGIN).hostname,
  });
  return auth.api.verifyPasskeyRegistration({ headers, body: { response } });
};
const passkeys = () => (sqlite.query("SELECT COUNT(*) AS n FROM passkey").get() as { n: number }).n;

describe("invitation lifecycle", () => {
  test("issues an invitation that stores only the token hash", async () => {
    const invitation = await issue();
    const row = sqlite.query("SELECT token_hash, email FROM invitation").get() as {
      token_hash: string;
      email: string;
    };
    expect(row.email).toBe("person@example.com");
    expect(row.token_hash).toBe(await sha256Hex(invitation.token));
    expect(row.token_hash).not.toBe(invitation.token);
  });

  test("resolves a valid token and rejects unknown, missing and expired tokens", async () => {
    const invitation = await issue();
    expect((await resolveInvitation(env.DB, invitation.token)).email).toBe("person@example.com");
    await expect(resolveInvitation(env.DB, "unknown")).rejects.toThrow();
    await expect(resolveInvitation(env.DB, null)).rejects.toThrow();
    sqlite.exec("UPDATE invitation SET expires_at = 1");
    await expect(resolveInvitation(env.DB, invitation.token)).rejects.toThrow();
  });

  test("consumes an invitation exactly once", async () => {
    const invitation = await issue();
    await consumeInvitation(env.DB, invitation.token);
    await expect(consumeInvitation(env.DB, invitation.token)).rejects.toThrow();
    await expect(resolveInvitation(env.DB, invitation.token)).rejects.toThrow();
  });

  test("does not resolve or consume a revoked invitation", async () => {
    const invitation = await issue();
    sqlite.exec("UPDATE invitation SET revoked_at = 1");
    await expect(resolveInvitation(env.DB, invitation.token)).rejects.toThrow();
    await expect(consumeInvitation(env.DB, invitation.token)).rejects.toThrow();
  });

  test("creates a user Better Auth can read and an 'invite' link", async () => {
    const invitation = await issue();
    expect(invitation.kind).toBe("invite");
    expect(invitation.createdUser).toBe(true);
    const found = await (await auth.$context).internalAdapter.findUserByEmail("person@example.com");
    expect(found?.user.id).toBe(invitation.userId);
    expect(found?.user.emailVerified).toBe(true);
    expect(sqlite.query("SELECT kind FROM invitation").get()).toEqual({ kind: "invite" });
  });

  test("reissues to a known user without a passkey, replacing the earlier link", async () => {
    const first = await issue();
    const second = await issue();
    expect(second.kind).toBe("invite");
    expect(second.createdUser).toBe(false);
    expect(sqlite.query("SELECT COUNT(*) AS n FROM invitation").get()).toEqual({ n: 1 });
    await expect(resolveInvitation(env.DB, first.token)).rejects.toThrow();
  });

  test("issues a short-lived recovery link to a user who has a passkey, revoking nothing", async () => {
    const invitation = await issue();
    addPasskey(invitation.userId);
    await consumeInvitation(env.DB, invitation.token);
    const recovery = await issue();
    expect(recovery.kind).toBe("recovery");
    expect(recovery.expiresAt - recovery.createdAt).toBe(RECOVERY_DAYS * 86_400_000);
    expect(sqlite.query("SELECT COUNT(*) AS n FROM passkey").get()).toEqual({ n: 1 });
    expect((await resolveInvitation(env.DB, recovery.token)).kind).toBe("recovery");
  });

  test("cancelUnsentInvitation removes an unused invitation and the user it created", async () => {
    const invitation = await issue();
    await cancelUnsentInvitation(env.DB, invitation);
    expect(sqlite.query("SELECT COUNT(*) AS n FROM invitation").get()).toEqual({ n: 0 });
    expect(sqlite.query('SELECT COUNT(*) AS n FROM "user"').get()).toEqual({ n: 0 });
  });

  test("cancelUnsentInvitation keeps a user it did not create", async () => {
    const first = await issue();
    const recovery = await issue();
    await cancelUnsentInvitation(env.DB, recovery);
    expect(first.createdUser).toBe(true);
    expect(sqlite.query('SELECT COUNT(*) AS n FROM "user"').get()).toEqual({ n: 1 });
  });

  test("reports registration complete only after use and a stored passkey", async () => {
    const invitation = await issue();
    expect(await invitationRegistrationComplete(env.DB, invitation.token)).toBe(false);
    await consumeInvitation(env.DB, invitation.token);
    expect(await invitationRegistrationComplete(env.DB, invitation.token)).toBe(false);
    const row = sqlite.query("SELECT user_id FROM invitation").get() as { user_id: string };
    addPasskey(row.user_id);
    expect(await invitationRegistrationComplete(env.DB, invitation.token)).toBe(true);
    expect(await invitationRegistrationComplete(env.DB, "")).toBe(false);
  });
});

describe("invitation registration", () => {

  test("registers a passkey using the invitation header and consumes the invitation", async () => {
    const invitation = await issue();
    await registerWith(invitation.token);
    expect(passkeys()).toBe(1);
    expect(sqlite.query("SELECT name FROM passkey").get()).toEqual({ name: "person@example.com" });
    await expect(resolveInvitation(env.DB, invitation.token)).rejects.toThrow();
  });

  test("ignores a token supplied in the query string", async () => {
    const invitation = await issue();
    await expect(registerWith(null, { context: invitation.token })).rejects.toThrow();
    expect(passkeys()).toBe(0);
    expect((await resolveInvitation(env.DB, invitation.token)).email).toBe("person@example.com");
  });

  test("rejects an unknown token", async () => {
    await expect(registerWith("unknown")).rejects.toThrow();
    expect(passkeys()).toBe(0);
  });

  test("rejects a token issued to another user and burns nothing", async () => {
    const other = await issue("other@example.com");
    const mine = await issue();
    await expect(completeInvitation(env.DB, other.token, mine.userId, "cred")).rejects.toThrow();
    expect((await resolveInvitation(env.DB, other.token)).email).toBe("other@example.com");
  });
});

describe("recovery", () => {
  const count = (sql: string) => (sqlite.query(sql).get() as { n: number }).n;

  async function enrolledUser(email = "person@example.com") {
    const enrolled = await signedInUser(sqlite, auth, { email, passkeys: 2 });
    const id = enrolled.user.id;
    sqlite.exec(`
      INSERT OR IGNORE INTO oauthClient (id, clientId, redirectUris) VALUES ('c1', 'client', '[]');
      INSERT INTO oauthRefreshToken (id, token, clientId, userId, expiresAt, createdAt, scopes)
        VALUES ('r-${id}', 'rt-${id}', 'client', '${id}', '2999-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z', 'openid');
      INSERT INTO oauthAccessToken (id, token, clientId, userId, refreshId, expiresAt, createdAt, scopes)
        VALUES ('a-${id}', 'at-${id}', 'client', '${id}', 'r-${id}', '2999-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z', 'openid');
      INSERT INTO oauthConsent (id, clientId, userId, scopes, createdAt, updatedAt)
        VALUES ('k-${id}', 'client', '${id}', 'openid', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z');
    `);
    return enrolled;
  }

  const grants = (userId: string) => ({
    passkeys: count(`SELECT COUNT(*) AS n FROM passkey WHERE userId = '${userId}'`),
    sessions: count(`SELECT COUNT(*) AS n FROM session WHERE userId = '${userId}'`),
    accessTokens: count(`SELECT COUNT(*) AS n FROM oauthAccessToken WHERE userId = '${userId}'`),
    refreshTokens: count(`SELECT COUNT(*) AS n FROM oauthRefreshToken WHERE userId = '${userId}'`),
    consents: count(`SELECT COUNT(*) AS n FROM oauthConsent WHERE userId = '${userId}'`),
  });
  const all = { passkeys: 2, sessions: 1, accessTokens: 1, refreshTokens: 1, consents: 1 };
  const pendingCredential = () =>
    (sqlite.query("SELECT pending_credential_id AS id FROM invitation").get() as { id: string | null } | null)?.id ?? null;
  const insertPasskey = (userId: string, id: string, credentialId: string) =>
    sqlite.query(`INSERT INTO passkey (id, publicKey, userId, credentialID, counter, deviceType, backedUp)
      VALUES (?1, 'k', ?2, ?3, 0, 'singleDevice', 0)`).run(id, userId, credentialId);

  test("requesting recovery leaves passkeys, sessions and tokens intact", async () => {
    const { user } = await enrolledUser();
    const recovery = await issue();
    expect(recovery.kind).toBe("recovery");
    expect(grants(user.id)).toEqual(all);
  });

  test("completing recovery replaces old passkeys and revokes sessions and OAuth grants", async () => {
    const { user, passkeyIds } = await enrolledUser();
    const bystander = await enrolledUser("bystander@example.com");
    const recovery = await issue();
    await registerWith(recovery.token);

    expect(grants(user.id)).toEqual({ passkeys: 1, sessions: 0, accessTokens: 0, refreshTokens: 0, consents: 0 });
    const remaining = sqlite.query("SELECT id, name FROM passkey WHERE userId = ?1").get(user.id) as { id: string; name: string };
    expect(passkeyIds).not.toContain(remaining.id);
    expect(remaining.name).toBe("person@example.com");
    expect(grants(bystander.user.id)).toEqual(all);
    await expect(resolveInvitation(env.DB, recovery.token)).rejects.toThrow();
    expect(pendingCredential()).toBeNull();
    expect(await invitationRegistrationComplete(env.DB, recovery.token)).toBe(true);
  });

  test("a failed passkey insert during recovery revokes nothing", async () => {
    const { user } = await enrolledUser();
    const recovery = await issue();
    sqlite.exec(`CREATE TRIGGER fail_passkey_insert BEFORE INSERT ON passkey
      BEGIN SELECT RAISE(ABORT, 'insert failed'); END;`);
    await expect(registerWith(recovery.token)).rejects.toThrow();
    sqlite.exec("DROP TRIGGER fail_passkey_insert");

    expect(grants(user.id)).toEqual(all);
    await expect(resolveInvitation(env.DB, recovery.token)).rejects.toThrow();
    expect(pendingCredential()).not.toBeNull();
    expect(await invitationRegistrationComplete(env.DB, recovery.token)).toBe(false);

    // A new link clears the stale credential, and a fresh recovery then works.
    const retry = await issue();
    expect(pendingCredential()).toBeNull();
    await registerWith(retry.token);
    expect(grants(user.id)).toEqual({ passkeys: 1, sessions: 0, accessTokens: 0, refreshTokens: 0, consents: 0 });
  });

  test("only the verified credential completes a recovery", async () => {
    const { user } = await enrolledUser();
    const recovery = await issue();
    await completeInvitation(env.DB, recovery.token, user.id, "verified-cred");
    expect(pendingCredential()).toBe("verified-cred");
    insertPasskey(user.id, "other", "other-cred");
    expect(grants(user.id)).toEqual({ ...all, passkeys: 3 });
    insertPasskey(user.id, "verified", "verified-cred");
    expect(grants(user.id)).toEqual({ passkeys: 1, sessions: 0, accessTokens: 0, refreshTokens: 0, consents: 0 });
    expect(pendingCredential()).toBeNull();
  });

  test("an 'invite' link never revokes, even with a matching credential ID recorded", async () => {
    const { user } = await enrolledUser();
    await issue();
    sqlite.exec(`UPDATE invitation SET kind = 'invite', used_at = ${Date.now()}, pending_credential_id = 'cred-x'`);
    insertPasskey(user.id, "x", "cred-x");
    expect(grants(user.id)).toEqual({ ...all, passkeys: 3 });
  });

  test("an 'invite' link records no pending credential", async () => {
    const invitation = await issue();
    await completeInvitation(env.DB, invitation.token, invitation.userId, "cred");
    expect(pendingCredential()).toBeNull();
  });

  test("a passkey added through passkey management never triggers revocation", async () => {
    const { user, headers } = await enrolledUser();
    const recovery = await issue();
    sqlite.exec(`CREATE TRIGGER fail_passkey_insert BEFORE INSERT ON passkey
      BEGIN SELECT RAISE(ABORT, 'insert failed'); END;`);
    await expect(registerWith(recovery.token)).rejects.toThrow();
    sqlite.exec("DROP TRIGGER fail_passkey_insert");
    expect(pendingCredential()).not.toBeNull();

    await registerWith(null, {}, headers.get("cookie")!);
    expect(grants(user.id)).toEqual({ ...all, passkeys: 3 });
    expect(pendingCredential()).toBeNull();
  });

  test("a recovery link works once", async () => {
    await enrolledUser();
    const recovery = await issue();
    await registerWith(recovery.token);
    await expect(registerWith(recovery.token)).rejects.toThrow();
    expect(passkeys()).toBe(1);
  });

  test("an expired recovery link revokes nothing", async () => {
    const { user } = await enrolledUser();
    const recovery = await issue();
    sqlite.exec("UPDATE invitation SET expires_at = 1");
    await expect(completeInvitation(env.DB, recovery.token, user.id, "cred")).rejects.toThrow();
    expect(grants(user.id)).toEqual(all);
  });

  test("a recovery link replaced by a newer one revokes nothing", async () => {
    const { user } = await enrolledUser();
    const first = await issue();
    await issue();
    await expect(completeInvitation(env.DB, first.token, user.id, "cred")).rejects.toThrow();
    expect(grants(user.id)).toEqual(all);
  });

  test("completing a normal invitation revokes nothing", async () => {
    const bystander = await enrolledUser("bystander@example.com");
    const invitation = await issue();
    const context = await auth.$context;
    await context.internalAdapter.createSession(invitation.userId);
    await registerWith(invitation.token);
    expect(grants(invitation.userId)).toMatchObject({ passkeys: 1, sessions: 1 });
    expect(grants(bystander.user.id)).toEqual(all);
  });
});
