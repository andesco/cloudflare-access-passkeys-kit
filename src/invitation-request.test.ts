import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import type { Database } from "bun:sqlite";
import { handleInvitationRequest, readRequest } from "./invitation-request";
import { migratedDatabase, ORIGIN, testAuth, testEnv } from "./test/helpers";

const realFetch = globalThis.fetch;
let sqlite: Database;
let sent: unknown[];
let pending: Promise<unknown>[];
let ctx: ExecutionContext;

function policyResponse(emails: string[]) {
  return Response.json({
    success: true,
    result: {
      decision: "allow",
      reusable: true,
      include: emails.map((email) => ({ email: { email } })),
      exclude: [],
      require: [],
    },
  });
}

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
    EMAIL: { send: async (message: unknown) => { sent.push(message); return { messageId: "m1" }; } } as never,
    ...overrides,
  });
}

async function run(request: Request, env = envWith()) {
  const auth = testAuth(sqlite, env);
  const response = await handleInvitationRequest(request, env, () => auth, ctx);
  await Promise.all(pending);
  return response;
}

beforeEach(() => {
  sqlite = migratedDatabase();
  sent = [];
  pending = [];
  ctx = { waitUntil: (promise: Promise<unknown>) => { pending.push(promise); }, passThroughOnException() {} } as ExecutionContext;
  globalThis.fetch = (async () => policyResponse(["person@example.com"])) as unknown as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

describe("readRequest", () => {
  test("normalizes the email", async () => {
    expect(await readRequest(post({ email: " Person@Example.com " }))).toEqual({
      email: "person@example.com",
      turnstileToken: "",
    });
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
    const response = await run(new Request(`${ORIGIN}/api/invitations/request`));
    expect(response.status).toBe(405);
  });

  test("sends an invitation to an authorized email", async () => {
    const response = await run(post({ email: "person@example.com" }));
    expect(response.status).toBe(202);
    expect(sent).toHaveLength(1);
    expect((sent[0] as { text: string }).text).toContain(`${ORIGIN}/invite#`);
  });

  test("returns the same response and sends nothing for an unlisted email", async () => {
    const authorized = await (await run(post({ email: "person@example.com" }))).text();
    sent.length = 0;
    const unlisted = await run(post({ email: "stranger@example.com" }));
    expect(unlisted.status).toBe(202);
    expect(await unlisted.text()).toBe(authorized);
    expect(sent).toHaveLength(0);
  });

  test("rate-limits before reading the body", async () => {
    let bodyRead = false;
    const request = post({ email: "person@example.com" });
    Object.defineProperty(request, "body", { get() { bodyRead = true; return null; } });
    const env = envWith({ INVITE_RATE_LIMITER: { limit: async () => ({ success: false }) } });
    const response = await run(request, env);
    expect(response.status).toBe(202);
    expect(bodyRead).toBe(false);
    expect(sent).toHaveLength(0);
  });

  test("requires a valid Turnstile token when enabled", async () => {
    globalThis.fetch = (async (input: RequestInfo | URL) =>
      String(input).includes("siteverify")
        ? Response.json({ success: false })
        : policyResponse(["person@example.com"])) as unknown as typeof fetch;
    const env = envWith({ TURNSTILE_ENABLED: "true", TURNSTILE_SECRET_KEY: "secret" });
    await run(post({ email: "person@example.com", turnstileToken: "bad" }), env);
    await run(post({ email: "person@example.com" }), env);
    expect(sent).toHaveLength(0);
  });

  test("removes the invitation when email delivery is rejected", async () => {
    const env = envWith({ EMAIL: { send: async () => { throw new Error("rejected"); } } as never });
    await run(post({ email: "person@example.com" }), env);
    expect(sqlite.query("SELECT COUNT(*) AS n FROM invitation").get()).toEqual({ n: 0 });
  });
});
