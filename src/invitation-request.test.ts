import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import type { Database } from "bun:sqlite";
import { hmacSha256Hex } from "./crypto";
import {
  REQUEST_COOLDOWN_MS,
  eligibility,
  cooldownCanonicalEmail,
  handleInvitationRequest,
  readRequest,
} from "./invitation-request";
import { migratedDatabase, ORIGIN, signedInUser, testAuth, testEnv } from "./test/helpers";

interface SentMail { to: string; subject: string; text: string; html: string }

const ELIGIBLE = new Set(["person@example.com", "member@example.com"]);
const realEligibility = eligibility.isEmailEligible;
const realConsoleError = console.error;

let sqlite: Database;
let sent: SentMail[];
let pending: Promise<unknown>[];
let checked: string[];
let errors: string[];
let ctx: ExecutionContext;

function post(body: unknown, init: RequestInit = {}) {
  return new Request(`${ORIGIN}/api/invitations/request`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
    ...init,
  });
}

function envWith(overrides: Partial<Env> = {}) {
  return testEnv(sqlite, {
    EMAIL: { send: async (message: SentMail) => { sent.push(message); return { messageId: "m1" }; } } as never,
    ...overrides,
  });
}

async function run(request: Request, env = envWith()) {
  const response = await handleInvitationRequest(request, env, ctx);
  await Promise.all(pending);
  pending = [];
  return response;
}

async function snapshot(response: Response) {
  return {
    status: response.status,
    headers: [...response.headers].sort(),
    body: await response.text(),
  };
}

const count = (sql: string) => (sqlite.query(sql).get() as { n: number }).n;
const expireCooldowns = () =>
  sqlite.exec(`UPDATE request_cooldown SET last_request_at = last_request_at - ${REQUEST_COOLDOWN_MS}`);

beforeEach(() => {
  sqlite = migratedDatabase();
  sent = [];
  pending = [];
  checked = [];
  errors = [];
  ctx = { waitUntil: (promise: Promise<unknown>) => { pending.push(promise); }, passThroughOnException() {} } as ExecutionContext;
  eligibility.isEmailEligible = async (_env, email) => {
    checked.push(email);
    return ELIGIBLE.has(email);
  };
  console.error = (...args: unknown[]) => { errors.push(args.map(String).join(" ")); };
});

afterEach(() => {
  eligibility.isEmailEligible = realEligibility;
  console.error = realConsoleError;
});

describe("readRequest", () => {
  test("normalizes the email", async () => {
    expect(await readRequest(post({ email: " Person@Example.com " }))).toEqual({ email: "person@example.com", turnstileToken: "" });
  });

  test("rejects non-JSON, malformed, invalid and oversized bodies", async () => {
    expect(await readRequest(post("{}", { headers: { "content-type": "text/plain" } }))).toBeNull();
    expect(await readRequest(post("not json"))).toBeNull();
    expect(await readRequest(post({ email: "nope" }))).toBeNull();
    expect(await readRequest(post({ email: "a@b.co", pad: "x".repeat(5000) }))).toBeNull();
  });
});

describe("handleInvitationRequest", () => {
  test("rejects non-POST methods", async () => {
    expect((await run(new Request(`${ORIGIN}/api/invitations/request`))).status).toBe(405);
  });

  test("rejects a malformed request with 400 and does no address work", async () => {
    const response = await run(post({ email: "nope" }));
    expect(response.status).toBe(400);
    expect(pending).toHaveLength(0);
    expect(count("SELECT COUNT(*) AS n FROM request_cooldown")).toBe(0);
  });

  test("rate-limits per IP before reading the body", async () => {
    let bodyRead = false;
    let key = "";
    const request = post({ email: "person@example.com" }, { headers: { "content-type": "application/json", "cf-connecting-ip": "192.0.2.1" } });
    Object.defineProperty(request, "body", { get() { bodyRead = true; return null; } });
    const env = envWith({ INVITE_RATE_LIMITER: { limit: async (input: { key: string }) => { key = input.key; return { success: false }; } } } as never);
    const response = await run(request, env);
    expect(response.status).toBe(429);
    expect(key).toBe("192.0.2.1");
    expect(bodyRead).toBe(false);
    expect(checked).toHaveLength(0);
    expect(sent).toHaveLength(0);
  });

  test("sends an invitation to an eligible new address", async () => {
    const response = await run(post({ email: "Person@Example.com" }));
    expect(response.status).toBe(202);
    expect(sent).toHaveLength(1);
    expect(sent[0]!.to).toBe("person@example.com");
    expect(sent[0]!.subject).toContain("invitation");
    expect(sent[0]!.text).toContain(`${ORIGIN}/invite#`);
    expect(sqlite.query("SELECT kind FROM invitation").get()).toEqual({ kind: "invite" });
  });

  describe("Turnstile", () => {
    const realFetch = globalThis.fetch;
    let verifyCalls: URLSearchParams[];
    let verdict: boolean;
    const turnstileEnv = () => envWith({ TURNSTILE_ENABLED: "true", TURNSTILE_SECRET_KEY: "secret" });

    beforeEach(() => {
      verifyCalls = [];
      verdict = false;
      globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
        verifyCalls.push(init?.body as URLSearchParams);
        return Response.json({ success: verdict });
      }) as unknown as typeof fetch;
    });
    afterEach(() => { globalThis.fetch = realFetch; });

    test("rejects a missing or invalid token before any address-dependent work", async () => {
      const missing = await run(post({ email: "person@example.com" }), turnstileEnv());
      const bad = await run(post({ email: "person@example.com", turnstileToken: "bad" }), turnstileEnv());
      expect(missing.status).toBe(403);
      expect(bad.status).toBe(403);
      expect((await missing.json()) as unknown).toEqual({ error: "Verification failed" });
      expect(verifyCalls).toHaveLength(1);
      expect(pending).toHaveLength(0);
      expect(checked).toHaveLength(0);
      expect(sent).toHaveLength(0);
      expect(count("SELECT COUNT(*) AS n FROM request_cooldown")).toBe(0);
    });

    test("fails the same way for eligible and ineligible addresses", async () => {
      const a = await snapshot(await run(post({ email: "person@example.com", turnstileToken: "bad" }), turnstileEnv()));
      const b = await snapshot(await run(post({ email: "stranger@example.com", turnstileToken: "bad" }), turnstileEnv()));
      expect(b).toEqual(a);
    });

    test("fails closed when the secret is missing or verification throws", async () => {
      const noSecret = envWith({ TURNSTILE_ENABLED: "true" });
      expect((await run(post({ email: "person@example.com", turnstileToken: "t" }), noSecret)).status).toBe(403);
      globalThis.fetch = (async () => { throw new Error("network"); }) as unknown as typeof fetch;
      expect((await run(post({ email: "person@example.com", turnstileToken: "t" }), turnstileEnv())).status).toBe(403);
      expect(sent).toHaveLength(0);
    });

    test("accepts a valid token, passes the client IP, and answers 202 before address work", async () => {
      verdict = true;
      const request = post({ email: "person@example.com", turnstileToken: "good" }, {
        headers: { "content-type": "application/json", "cf-connecting-ip": "192.0.2.7" },
      });
      const response = await run(request, turnstileEnv());
      expect(response.status).toBe(202);
      expect(verifyCalls[0]!.get("response")).toBe("good");
      expect(verifyCalls[0]!.get("remoteip")).toBe("192.0.2.7");
      expect(sent).toHaveLength(1);
    });

    test("is not consulted when disabled", async () => {
      const response = await run(post({ email: "person@example.com" }));
      expect(response.status).toBe(202);
      expect(verifyCalls).toHaveLength(0);
    });
  });

  test("answers before the eligibility lookup finishes", async () => {
    let release!: (value: boolean) => void;
    let entered!: () => void;
    const lookupEntered = new Promise<void>((resolve) => { entered = resolve; });
    eligibility.isEmailEligible = () => new Promise<boolean>((resolve) => { release = resolve; entered(); });
    const response = await handleInvitationRequest(post({ email: "person@example.com" }), envWith(), ctx);
    expect(response.status).toBe(202);
    expect(sent).toHaveLength(0);
    // The cooldown claim (async HMAC + DB) runs first, so wait until the lookup has really started.
    await lookupEntered;
    expect(sent).toHaveLength(0);
    release(true);
    await Promise.all(pending);
    expect(sent).toHaveLength(1);
  });

  test("gives an identical response for eligible, ineligible, cooling-down and existing-user addresses", async () => {
    const env = envWith();
    await signedInUser(sqlite, testAuth(sqlite, env), { email: "member@example.com", passkeys: 1 });
    await signedInUser(sqlite, testAuth(sqlite, env), { email: "former@example.com", passkeys: 1 });

    const eligibleNew = await snapshot(await run(post({ email: "person@example.com" }), env));
    const coolingDown = await snapshot(await run(post({ email: "person@example.com" }), env));
    const ineligible = await snapshot(await run(post({ email: "stranger@example.com" }), env));
    const existingEligible = await snapshot(await run(post({ email: "member@example.com" }), env));
    const existingIneligible = await snapshot(await run(post({ email: "former@example.com" }), env));

    expect(eligibleNew.status).toBe(202);
    for (const other of [coolingDown, ineligible, existingEligible, existingIneligible]) {
      expect(other).toEqual(eligibleNew);
    }
    expect(sent.map((mail) => mail.to)).toEqual(["person@example.com", "member@example.com"]);
  });

  test("a send failure does not change the response, cancels the link and keeps the cooldown", async () => {
    const ok = await snapshot(await run(post({ email: "member@example.com" })));
    expireCooldowns();
    sqlite.exec('DELETE FROM invitation; DELETE FROM "user"');
    const env = envWith({ EMAIL: { send: async () => { throw new Error("rejected"); } } as never });
    const failed = await snapshot(await run(post({ email: "person@example.com" }), env));
    expect(failed).toEqual(ok);
    expect(count("SELECT COUNT(*) AS n FROM invitation")).toBe(0);
    expect(count('SELECT COUNT(*) AS n FROM "user"')).toBe(0);
    expect(errors.some((line) => line.includes("rejected"))).toBe(true);

    await run(post({ email: "person@example.com" }));
    expect(sent).toHaveLength(1); // only the first, unrelated address; the retry is still cooling down
  });

  test("never logs the address", async () => {
    eligibility.isEmailEligible = async (_env, email) => { throw new Error(`lookup failed for ${email}`); };
    await run(post({ email: "person@example.com" }));
    expect(errors).toHaveLength(1);
    expect(errors.join("\n")).not.toContain("person@example.com");
  });
});

describe("per-address cooldown", () => {
  test("stores an HMAC of the normalized address, never the address", async () => {
    await run(post({ email: " Person@Example.com " }));
    const rows = sqlite.query("SELECT email_hash, last_request_at FROM request_cooldown").all() as {
      email_hash: string;
      last_request_at: number;
    }[];
    expect(rows).toHaveLength(1);
    expect(rows[0]!.email_hash).toBe(await hmacSha256Hex(envWith().BETTER_AUTH_SECRET, "person@example.com"));
    expect(rows[0]!.email_hash).not.toContain("@");
    expect(rows[0]!.email_hash).toMatch(/^[0-9a-f]{64}$/u);
  });

  test("blocks a second request for an eligible address within the window, then releases it", async () => {
    await run(post({ email: "person@example.com" }));
    await run(post({ email: "PERSON@example.com" }));
    expect(sent).toHaveLength(1);
    expect(checked).toEqual(["person@example.com"]);
    expireCooldowns();
    await run(post({ email: "person@example.com" }));
    expect(sent).toHaveLength(2);
  });

  test("blocks a second request for an ineligible address within the window, then releases it", async () => {
    await run(post({ email: "stranger@example.com" }));
    await run(post({ email: "stranger@example.com" }));
    expect(checked).toEqual(["stranger@example.com"]);
    expect(count("SELECT COUNT(*) AS n FROM request_cooldown")).toBe(1);
    expireCooldowns();
    await run(post({ email: "stranger@example.com" }));
    expect(checked).toEqual(["stranger@example.com", "stranger@example.com"]);
    expect(sent).toHaveLength(0);
    expect(count('SELECT COUNT(*) AS n FROM "user"')).toBe(0);
  });

  test("canonicalizes only for the cooldown key: strips a +tag, keeps dots", () => {
    expect(cooldownCanonicalEmail(" Victim+1@Example.com ")).toBe("victim@example.com");
    expect(cooldownCanonicalEmail("victim+a+b@example.com")).toBe("victim@example.com");
    expect(cooldownCanonicalEmail("first.last@example.com")).toBe("first.last@example.com");
    expect(cooldownCanonicalEmail("first.last+x@example.com")).toBe("first.last@example.com");
    expect(cooldownCanonicalEmail("victim@sub+domain.example")).toBe("victim@sub+domain.example");
  });

  test("plus-addressed variants share one cooldown slot", async () => {
    eligibility.isEmailEligible = async (_env, email) => { checked.push(email); return email.endsWith("@example.com"); };
    await run(post({ email: "victim+1@example.com" }));
    await run(post({ email: "victim+2@example.com" }));
    await run(post({ email: "victim@example.com" }));
    expect(checked).toEqual(["victim+1@example.com"]);
    expect(sent.map((mail) => mail.to)).toEqual(["victim+1@example.com"]);
    expect(count('SELECT COUNT(*) AS n FROM "user"')).toBe(1);
    expect(sqlite.query('SELECT email FROM "user"').get()).toEqual({ email: "victim+1@example.com" });
    expect(count("SELECT COUNT(*) AS n FROM request_cooldown")).toBe(1);
  });

  test("dotted variants keep separate cooldown slots", async () => {
    await run(post({ email: "first.last@example.com" }));
    await run(post({ email: "firstlast@example.com" }));
    expect(checked).toEqual(["first.last@example.com", "firstlast@example.com"]);
  });

  test("claims separately per address", async () => {
    await run(post({ email: "person@example.com" }));
    await run(post({ email: "stranger@example.com" }));
    expect(checked).toEqual(["person@example.com", "stranger@example.com"]);
  });
});

describe("recovery requests", () => {
  test("an eligible user with a passkey gets a recovery link and loses nothing yet", async () => {
    const env = envWith();
    const { user } = await signedInUser(sqlite, testAuth(sqlite, env), { email: "member@example.com", passkeys: 2 });
    const response = await run(post({ email: "member@example.com" }), env);
    expect(response.status).toBe(202);
    expect(sent).toHaveLength(1);
    expect(sent[0]!.subject).toContain("Recover");
    expect(sent[0]!.text).toContain(`${ORIGIN}/invite#`);
    expect(sent[0]!.text).toContain("removes all of your existing passkeys");
    expect(sent[0]!.text).toContain("you can ignore this email");
    expect(sqlite.query("SELECT kind FROM invitation").get()).toEqual({ kind: "recovery" });
    expect(count(`SELECT COUNT(*) AS n FROM passkey WHERE userId = '${user.id}'`)).toBe(2);
    expect(count(`SELECT COUNT(*) AS n FROM session WHERE userId = '${user.id}'`)).toBe(1);
  });

  test("an ineligible user with a passkey gets nothing and keeps everything", async () => {
    const env = envWith();
    const { user } = await signedInUser(sqlite, testAuth(sqlite, env), { email: "former@example.com", passkeys: 1 });
    await run(post({ email: "former@example.com" }), env);
    expect(sent).toHaveLength(0);
    expect(count("SELECT COUNT(*) AS n FROM invitation")).toBe(0);
    expect(count(`SELECT COUNT(*) AS n FROM passkey WHERE userId = '${user.id}'`)).toBe(1);
    expect(count(`SELECT COUNT(*) AS n FROM "user" WHERE id = '${user.id}'`)).toBe(1);
  });
});
