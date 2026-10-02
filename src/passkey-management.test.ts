import { beforeEach, describe, expect, test } from "bun:test";
import type { Database } from "bun:sqlite";
import {
  assertCanAddPasskey,
  assertCanRemovePasskey,
  isRecentSignIn,
  MAX_PASSKEYS,
  RECENT_SIGN_IN_MESSAGE,
  RECENT_SIGN_IN_MS,
} from "./passkey-management";
import { migratedDatabase, ORIGIN, signedInUser, testAuth, testEnv } from "./test/helpers";
import { registrationResponse } from "./test/webauthn";

const NOW = Date.parse("2026-10-02T12:00:00Z");

describe("guards", () => {
  test("isRecentSignIn accepts only sign-ins within the window", () => {
    expect(isRecentSignIn(NOW - RECENT_SIGN_IN_MS, NOW)).toBe(true);
    expect(isRecentSignIn(NOW - RECENT_SIGN_IN_MS - 1, NOW)).toBe(false);
    expect(isRecentSignIn("not a date", NOW)).toBe(false);
  });

  test("adding requires a recent sign-in and respects the passkey cap", () => {
    expect(() => assertCanAddPasskey({ sessionCreatedAt: NOW, passkeyCount: 1 }, NOW)).not.toThrow();
    expect(() => assertCanAddPasskey({ sessionCreatedAt: NOW - 3_600_000, passkeyCount: 1 }, NOW)).toThrow(
      RECENT_SIGN_IN_MESSAGE,
    );
    expect(() => assertCanAddPasskey({ sessionCreatedAt: NOW, passkeyCount: MAX_PASSKEYS }, NOW)).toThrow();
  });

  test("removing requires a recent sign-in and never the last passkey", () => {
    expect(() => assertCanRemovePasskey({ sessionCreatedAt: NOW, passkeyCount: 2 }, NOW)).not.toThrow();
    expect(() => assertCanRemovePasskey({ sessionCreatedAt: NOW, passkeyCount: 1 }, NOW)).toThrow("only passkey");
    expect(() => assertCanRemovePasskey({ sessionCreatedAt: NOW - 3_600_000, passkeyCount: 2 }, NOW)).toThrow(
      RECENT_SIGN_IN_MESSAGE,
    );
  });
});

describe("passkey endpoints", () => {
  let sqlite: Database;
  let sent: { to: string; subject: string }[];
  let env: Env;
  let auth: ReturnType<typeof testAuth>;
  const passkeyCount = () => (sqlite.query("SELECT COUNT(*) AS n FROM passkey").get() as { n: number }).n;

  beforeEach(() => {
    sqlite = migratedDatabase();
    sent = [];
    env = testEnv(sqlite, {
      EMAIL: { send: async (message: { to: string; subject: string }) => { sent.push(message); return { messageId: "m" }; } } as never,
    });
    auth = testAuth(sqlite, env);
  });

  test("removes a passkey and notifies the user", async () => {
    const { headers, passkeyIds } = await signedInUser(sqlite, auth);
    await auth.api.deletePasskey({ headers, body: { id: passkeyIds[0]! } });
    expect(passkeyCount()).toBe(1);
    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({ to: "person@example.com" });
  });

  test("refuses to remove the only passkey", async () => {
    const { headers, passkeyIds } = await signedInUser(sqlite, auth, { passkeys: 1 });
    await expect(auth.api.deletePasskey({ headers, body: { id: passkeyIds[0]! } })).rejects.toThrow("only passkey");
    expect(passkeyCount()).toBe(1);
    expect(sent).toHaveLength(0);
  });

  test("refuses to remove a passkey from a stale session", async () => {
    const { headers, passkeyIds } = await signedInUser(sqlite, auth, { sessionAgeMs: 10 * 60_000 });
    await expect(auth.api.deletePasskey({ headers, body: { id: passkeyIds[0]! } })).rejects.toThrow(
      RECENT_SIGN_IN_MESSAGE,
    );
    expect(passkeyCount()).toBe(2);
  });

  test("does not let a user remove another user's passkey", async () => {
    const other = await signedInUser(sqlite, auth, { email: "other@example.com" });
    const { headers } = await signedInUser(sqlite, auth, { email: "me@example.com" });
    await expect(auth.api.deletePasskey({ headers, body: { id: other.passkeyIds[0]! } })).rejects.toThrow();
    expect(passkeyCount()).toBe(4);
  });

  test("renames within the length limit only", async () => {
    const { headers, passkeyIds } = await signedInUser(sqlite, auth);
    await auth.api.updatePasskey({ headers, body: { id: passkeyIds[0]!, name: "Work laptop" } });
    expect(sqlite.query("SELECT name FROM passkey WHERE id = 'pk-0'").get()).toEqual({ name: "Work laptop" });
    await expect(
      auth.api.updatePasskey({ headers, body: { id: passkeyIds[0]!, name: "x".repeat(65) } }),
    ).rejects.toThrow("limited");
  });
});

describe("adding a passkey while signed in", () => {
  let sqlite: Database;
  let sent: unknown[];
  let env: Env;
  let auth: ReturnType<typeof testAuth>;
  const passkeyCount = () => (sqlite.query("SELECT COUNT(*) AS n FROM passkey").get() as { n: number }).n;

  beforeEach(() => {
    sqlite = migratedDatabase();
    sent = [];
    env = testEnv(sqlite, {
      EMAIL: { send: async (message: unknown) => { sent.push(message); return { messageId: "m" }; } } as never,
    });
    auth = testAuth(sqlite, env);
  });

  async function addPasskey(headers: Headers) {
    const optionsResponse = await auth.api.generatePasskeyRegistrationOptions({
      headers,
      query: {},
      asResponse: true,
    });
    const options = await optionsResponse.json() as { challenge: string };
    const challengeCookie = optionsResponse.headers.getSetCookie().map((value) => value.split(";")[0]!);
    const response = await registrationResponse({
      challenge: options.challenge,
      origin: ORIGIN,
      rpId: new URL(ORIGIN).hostname,
    });
    const withChallenge = new Headers(headers);
    withChallenge.set("cookie", [headers.get("cookie"), ...challengeCookie].join("; "));
    withChallenge.set("origin", ORIGIN);
    return auth.api.verifyPasskeyRegistration({ headers: withChallenge, body: { response } });
  }

  test("registers a second passkey labelled with the account email and sends a notice", async () => {
    const { headers } = await signedInUser(sqlite, auth, { passkeys: 1 });
    await addPasskey(headers);
    expect(passkeyCount()).toBe(2);
    expect(sqlite.query("SELECT name FROM passkey ORDER BY createdAt DESC LIMIT 1").get()).toEqual({
      name: "person@example.com",
    });
    expect(sent).toHaveLength(1);
  });

  test("requires a recent passkey sign-in", async () => {
    const { headers } = await signedInUser(sqlite, auth, { passkeys: 1, sessionAgeMs: 10 * 60_000 });
    await expect(addPasskey(headers)).rejects.toThrow(RECENT_SIGN_IN_MESSAGE);
    expect(passkeyCount()).toBe(1);
  });

  test("enforces the passkey cap", async () => {
    const { headers } = await signedInUser(sqlite, auth, { passkeys: MAX_PASSKEYS });
    await expect(addPasskey(headers)).rejects.toThrow("maximum");
  });
});
