import { beforeEach, describe, expect, test } from "bun:test";
import type { Database } from "bun:sqlite";
import { sha256Hex } from "./crypto";
import {
  cancelUnsentInvitation,
  consumeInvitation,
  invitationRegistrationComplete,
  issueInvitation,
  resolveInvitation,
} from "./invitations";
import { migratedDatabase, testAuth, testEnv } from "./test/helpers";

let sqlite: Database;
let env: Env;
let auth: ReturnType<typeof testAuth>;

beforeEach(() => {
  sqlite = migratedDatabase();
  env = testEnv(sqlite);
  auth = testAuth(sqlite, env);
});

async function issue(email = "person@example.com") {
  const invitation = await issueInvitation(auth, env.DB, email, 7);
  if (!invitation) throw new Error("expected an invitation");
  return invitation;
}

function addPasskey(userId: string) {
  sqlite.exec(
    `INSERT INTO passkey (id, publicKey, userId, credentialID, counter, deviceType, backedUp)
     VALUES ('p1', 'key', '${userId}', 'cred', 0, 'singleDevice', 0)`,
  );
}

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

  test("suppresses repeated invitations for ten minutes", async () => {
    await issue();
    expect(await issueInvitation(auth, env.DB, "person@example.com", 7)).toBeNull();
    sqlite.exec("UPDATE invitation SET created_at = created_at - 700000");
    const second = await issueInvitation(auth, env.DB, "person@example.com", 7);
    expect(second).not.toBeNull();
    expect(sqlite.query("SELECT COUNT(*) AS n FROM invitation").get()).toEqual({ n: 1 });
  });

  test("does not invite a user who already has a passkey", async () => {
    const invitation = await issue();
    const row = sqlite.query("SELECT user_id FROM invitation").get() as { user_id: string };
    addPasskey(row.user_id);
    sqlite.exec("UPDATE invitation SET created_at = 1");
    expect(await issueInvitation(auth, env.DB, "person@example.com", 7)).toBeNull();
    expect(invitation.id).toBeTruthy();
  });

  test("cancelUnsentInvitation removes an unused invitation", async () => {
    const invitation = await issue();
    await cancelUnsentInvitation(env.DB, invitation);
    expect(sqlite.query("SELECT COUNT(*) AS n FROM invitation").get()).toEqual({ n: 0 });
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
