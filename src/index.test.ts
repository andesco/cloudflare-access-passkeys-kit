import { beforeEach, describe, expect, test } from "bun:test";
import worker from "./index";
import { redactPath } from "./redact";
import { migratedDatabase, ORIGIN, testEnv } from "./test/helpers";

const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
let env: Env;

beforeEach(() => {
  env = testEnv(migratedDatabase(), {
    ASSETS: { fetch: async () => new Response("<html></html>", { headers: { "content-type": "text/html" } }) } as never,
  });
});

const get = (path: string, base = ORIGIN) => worker.fetch(new Request(`${base}${path}`) as never, env, ctx);

describe("worker routing", () => {
  test("serves the sign-in page with strict security headers", async () => {
    const response = await get("/");
    expect(response.status).toBe(200);
    expect(response.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
  });

  test("allows Turnstile origins in the CSP only when enabled", async () => {
    expect((await get("/")).headers.get("content-security-policy")).not.toContain("challenges.cloudflare.com");
    env = { ...env, TURNSTILE_ENABLED: "true" };
    expect((await get("/")).headers.get("content-security-policy")).toContain("challenges.cloudflare.com");
  });

  test("hides raw .html assets and the invitation page for malformed tokens", async () => {
    expect((await get("/sign-in.html")).status).toBe(404);
    expect((await get("/invite/")).status).toBe(404);
    expect((await get("/invite/a/b")).status).toBe(404);
    expect((await get("/invite/abc")).status).toBe(200); // legacy path links
    expect((await get("/invite")).status).toBe(200);
  });

  test("rejects requests for any host other than PUBLIC_ORIGIN, including admin", async () => {
    const other = "https://worker.example.workers.dev";
    expect((await get("/health", other)).status).toBe(404);
    expect((await get("/__admin/v1/invitations", other)).status).toBe(404);
    expect((await get("/health")).status).toBe(200);
  });

  test("serves any host when PUBLIC_ORIGIN is unset", async () => {
    env = { ...env, PUBLIC_ORIGIN: "" };
    expect((await get("/health", "http://localhost:8787")).status).toBe(200);
  });

  test("requires the admin bearer token", async () => {
    expect((await get("/__admin/v1/invitations")).status).toBe(401);
  });

  test("reports invitation status through POST only, never a query string", async () => {
    const post = (body: string) =>
      worker.fetch(new Request(`${ORIGIN}/api/invitations/status`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
      }) as never, env, ctx);
    expect((await (await post(JSON.stringify({ token: "nope" }))).json()) as unknown).toEqual({ complete: false });
    expect((await (await post(JSON.stringify({ token: "x".repeat(200) }))).json()) as unknown).toEqual({ complete: false });
    expect((await (await post("not json")).json()) as unknown).toEqual({ complete: false });
    expect((await (await post("x".repeat(5000))).json()) as unknown).toEqual({ complete: false });
    expect((await get("/api/invitations/status?token=nope")).status).toBe(405);
  });
});

describe("redactPath", () => {
  test("hides invitation tokens but keeps other paths", () => {
    expect(redactPath("/invite/secret-token")).toBe("/invite/[redacted]");
    expect(redactPath("/api/config")).toBe("/api/config");
  });
});
