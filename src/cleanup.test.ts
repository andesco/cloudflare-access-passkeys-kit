import { beforeEach, describe, expect, test } from "bun:test";
import type { Database } from "bun:sqlite";
import { cleanup } from "./cleanup";
import { d1, migratedDatabase } from "./test/helpers";

const NOW = Date.parse("2026-10-02T00:00:00Z");
const DAY = 86_400_000;
const iso = (offsetDays: number) => new Date(NOW + offsetDays * DAY).toISOString();

let sqlite: Database;
let db: D1Database;

const count = (table: string) => (sqlite.query(`SELECT COUNT(*) AS n FROM "${table}"`).get() as { n: number }).n;

function addUser(id: string, opts: { passkey?: boolean; invitation?: { expiresDays: number; used?: boolean; revoked?: boolean } }) {
  sqlite.exec(`INSERT INTO "user" (id, name, email, emailVerified, createdAt, updatedAt)
    VALUES ('${id}', '${id}', '${id}@example.com', 1, '${iso(-90)}', '${iso(-90)}')`);
  if (opts.passkey) {
    sqlite.exec(`INSERT INTO passkey (id, publicKey, userId, credentialID, counter, deviceType, backedUp)
      VALUES ('pk-${id}', 'k', '${id}', 'c-${id}', 0, 'singleDevice', 0)`);
  }
  if (opts.invitation) {
    const { expiresDays, used, revoked } = opts.invitation;
    sqlite.exec(`INSERT INTO invitation (id, token_hash, email, user_id, expires_at, used_at, revoked_at, created_at)
      VALUES ('inv-${id}', 'h-${id}', '${id}@example.com', '${id}', ${NOW + expiresDays * DAY},
              ${used ? NOW : "NULL"}, ${revoked ? NOW : "NULL"}, ${NOW - 60 * DAY})`);
  }
}

beforeEach(() => {
  sqlite = migratedDatabase();
  db = d1(sqlite);
});

describe("cleanup", () => {
  test("removes only expired verifications, sessions and OAuth tokens", async () => {
    addUser("u1", { passkey: true });
    sqlite.exec(`
      INSERT INTO verification (id, identifier, value, expiresAt, createdAt, updatedAt) VALUES
        ('v-old', 'x', 'y', '${iso(-1)}', '${iso(-2)}', '${iso(-2)}'),
        ('v-new', 'x', 'y', '${iso(1)}', '${iso(0)}', '${iso(0)}');
      INSERT INTO session (id, expiresAt, token, createdAt, updatedAt, userId) VALUES
        ('s-old', '${iso(-1)}', 't1', '${iso(-9)}', '${iso(-9)}', 'u1'),
        ('s-new', '${iso(5)}', 't2', '${iso(0)}', '${iso(0)}', 'u1');
      INSERT INTO oauthClient (id, clientId, redirectUris) VALUES ('c1', 'client', '[]');
      INSERT INTO oauthAccessToken (id, token, clientId, userId, expiresAt, createdAt, scopes) VALUES
        ('a-old', 'a1', 'client', 'u1', '${iso(-1)}', '${iso(-2)}', 'openid'),
        ('a-new', 'a2', 'client', 'u1', '${iso(1)}', '${iso(0)}', 'openid');
    `);
    const result = await cleanup(db, NOW);
    expect(result).toMatchObject({ expiredVerifications: 1, expiredSessions: 1, expiredAccessTokens: 1 });
    expect(count("verification")).toBe(1);
    expect(count("session")).toBe(1);
    expect(count("oauthAccessToken")).toBe(1);
  });

  test("never matches dates stored in an unexpected format", async () => {
    addUser("u1", { passkey: true });
    sqlite.exec(`INSERT INTO session (id, expiresAt, token, createdAt, updatedAt, userId)
      VALUES ('s1', 1, 't1', 1, 1, 'u1')`);
    expect((await cleanup(db, NOW)).expiredSessions).toBe(0);
    expect(count("session")).toBe(1);
  });

  test("deletes users whose invitation lapsed unused, along with the invitation", async () => {
    addUser("lapsed", { invitation: { expiresDays: -40 } });
    addUser("revoked", { invitation: { expiresDays: -40, revoked: true } });
    await cleanup(db, NOW);
    expect(count("user")).toBe(0);
    expect(count("invitation")).toBe(0);
  });

  test("keeps users who are registered, recently invited, mid-registration or in recovery", async () => {
    addUser("registered", { passkey: true, invitation: { expiresDays: -40, used: true } });
    addUser("recent", { invitation: { expiresDays: -5 } });
    addUser("pending", { invitation: { expiresDays: 3 } });
    addUser("used-no-passkey", { invitation: { expiresDays: -40, used: true } });
    addUser("recovering", { passkey: true, invitation: { expiresDays: -40 } });
    await cleanup(db, NOW);
    expect(count("user")).toBe(5);
  });
});
