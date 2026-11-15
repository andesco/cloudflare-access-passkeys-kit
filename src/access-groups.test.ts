import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import type { Database } from "bun:sqlite";
import { isEmailEligible, MAX_GROUP_IDS, parseGroupIds } from "./access-groups";
import { migratedDatabase, testEnv } from "./test/helpers";

const BASE = "https://api.cloudflare.com/client/v4/accounts/account";
const G1 = "11111111-1111-4111-8111-111111111111";
const G2 = "22222222-2222-4222-8222-222222222222";
const G3 = "33333333333343338333333333333333";
const NESTED = "99999999-9999-4999-8999-999999999999";

type Json = Record<string, unknown>;

const email = (address: string) => ({ email: { email: address } });
const domain = (value: string) => ({ email_domain: { domain: value } });
const groupRule = (id: string) => ({ group: { id } });
const group = (id: string, include: unknown[], extra: Json = {}) => ({ id, name: `group ${id}`, include, exclude: [], require: [], ...extra });

let db: Database;
let env: Env;
let routes: Map<string, () => Response>;
let calls: string[];
let warnings: string[];
const realFetch = globalThis.fetch;
const realWarn = console.warn;

function ok(result: unknown): () => Response {
  return () => Response.json({ success: true, errors: [], result });
}

function serve(id: string, include: unknown[], extra: Json = {}) {
  routes.set(`/access/groups/${id}`, ok(group(id, include, extra)));
}

function configure(ids: string) {
  env = { ...env, ACCESS_GROUP_IDS: ids };
}

beforeEach(() => {
  db = migratedDatabase();
  env = testEnv(db, { ACCESS_GROUP_IDS: G1 });
  routes = new Map();
  calls = [];
  warnings = [];
  console.warn = (...args: unknown[]) => { warnings.push(args.map(String).join(" ")); };
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    expect(new Headers(init?.headers).get("authorization")).toBe("Bearer token");
    expect(init?.method ?? "GET").toBe("GET");
    const path = url.startsWith(BASE) ? url.slice(BASE.length) : url;
    calls.push(path);
    const handler = routes.get(path);
    return handler ? handler() : new Response("not found", { status: 404 });
  }) as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = realFetch;
  console.warn = realWarn;
});

const eligible = (address: string) => isEmailEligible(env, address);

describe("email and domain rules", () => {
  test("exact email matches case-insensitively and with whitespace", async () => {
    serve(G1, [email("Person@Example.com")]);
    expect(await eligible("  person@EXAMPLE.com ")).toBe(true);
    expect(await eligible("other@example.com")).toBe(false);
  });

  test("domain matches exactly, not subdomains, and accepts an @-prefixed rule", async () => {
    serve(G1, [domain("example.com"), domain("@Corp.Test")]);
    expect(await eligible("a@example.com")).toBe(true);
    expect(await eligible("a@corp.test")).toBe(true);
    expect(await eligible("a@sub.example.com")).toBe(false);
    expect(await eligible("a@example.com.evil")).toBe(false);
    expect(await eligible("a@other.test")).toBe(false);
  });

  test("malformed input emails are rejected without any fetch", async () => {
    serve(G1, [domain("example.com")]);
    for (const bad of ["", "   ", "@example.com", "a@", "a@b@example.com", "example.com"]) {
      expect(await eligible(bad)).toBe(false);
    }
    expect(calls).toHaveLength(0);
  });

  test("malformed email and domain rules never match", async () => {
    serve(G1, [
      { email: { email: "a@example.com" }, everyone: {} },
      { email: "b@example.com" },
      { email: { email: "c@example.com", extra: true } },
      domain(""),
      domain("x@y.test"),
      email("not-an-address"),
      "d@example.com",
      null,
    ]);
    for (const address of ["a@example.com", "b@example.com", "c@example.com", "d@example.com", "z@y.test"]) {
      expect(await eligible(address)).toBe(false);
    }
  });
});

describe("ignored include rules", () => {
  test("everyone alone grants nothing", async () => {
    serve(G1, [{ everyone: {} }]);
    expect(await eligible("anyone@example.com")).toBe(false);
  });

  test("everyone alongside an email: the email still matches, a different address does not", async () => {
    serve(G1, [{ everyone: {} }, email("person@example.com")]);
    expect(await eligible("person@example.com")).toBe(true);
    expect(await eligible("other@example.com")).toBe(false);
  });

  test("other include kinds are ignored and nested groups are not followed", async () => {
    serve(G1, [
      groupRule(NESTED),
      { email_list: { id: "list" } },
      { okta: { name: "eng", identity_provider_id: "x" } },
      { saml: { attribute_name: "a", attribute_value: "b" } },
      { geo: { country_code: "US" } },
      { ip: { ip: "10.0.0.0/8" } },
      { device_posture: { integration_uid: "x" } },
      { login_method: { id: "x" } },
      { auth_method: { auth_method: "mfa" } },
      { service_token: { token_id: "x" } },
      { any_valid_service_token: {} },
      { something_new: { value: "x" } },
      email("listed@example.com"),
    ]);
    serve(NESTED, [email("nested@example.com"), { everyone: {} }]);
    expect(await eligible("listed@example.com")).toBe(true);
    expect(await eligible("nested@example.com")).toBe(false);
    expect(calls).not.toContain(`/access/groups/${NESTED}`);
    expect(calls.every((path) => path === `/access/groups/${G1}`)).toBe(true);
  });

  test("a group whose include has only ignored rules grants nothing", async () => {
    serve(G1, [groupRule(NESTED), { email_list: { id: "list" } }]);
    serve(NESTED, [email("nested@example.com")]);
    expect(await eligible("nested@example.com")).toBe(false);
    expect(calls).toEqual([`/access/groups/${G1}`]);
  });
});

describe("exclude and require", () => {
  test("a matching exclude blocks an included address", async () => {
    serve(G1, [domain("example.com")], { exclude: [email("blocked@example.com"), domain("@banned.test")] });
    expect(await eligible("ok@example.com")).toBe(true);
    expect(await eligible("blocked@example.com")).toBe(false);
    serve(G1, [domain("banned.test")], { exclude: [domain("@banned.test")] });
    expect(await eligible("a@banned.test")).toBe(false);
  });

  test("an unsupported exclude rule disables the group, a second configured group still grants", async () => {
    configure(`${G1},${G2}`);
    serve(G1, [email("a@example.com"), email("b@example.com")], { exclude: [{ "github-organization": { name: "org" } }] });
    serve(G2, [email("b@example.com")]);
    expect(await eligible("a@example.com")).toBe(false);
    expect(await eligible("b@example.com")).toBe(true);
  });

  test("malformed or nested-group exclude rules disable the group", async () => {
    for (const rule of [{ email: "x@example.com" }, domain(""), groupRule(NESTED), { everyone: {} }, null]) {
      serve(G1, [email("a@example.com")], { exclude: [rule] });
      expect(await eligible("a@example.com")).toBe(false);
    }
    serve(G1, [email("a@example.com")], { exclude: "not-an-array" });
    expect(await eligible("a@example.com")).toBe(false);
    expect(calls).not.toContain(`/access/groups/${NESTED}`);
  });

  test("a non-empty require disables the group", async () => {
    serve(G1, [email("person@example.com")], { require: [email("person@example.com")] });
    expect(await eligible("person@example.com")).toBe(false);
    serve(G1, [email("person@example.com")], { require: "bad" });
    expect(await eligible("person@example.com")).toBe(false);
  });

  test("missing exclude and require are treated as empty", async () => {
    routes.set(`/access/groups/${G1}`, ok({ id: G1, include: [email("person@example.com")] }));
    expect(await eligible("person@example.com")).toBe(true);
  });

  test("a group without an include array grants nothing", async () => {
    routes.set(`/access/groups/${G1}`, ok({ id: G1, exclude: [] }));
    expect(await eligible("person@example.com")).toBe(false);
  });
});

describe("multiple groups and failures", () => {
  test("checks groups in order and stops at the first match", async () => {
    configure(`${G1} ${G2}`);
    serve(G1, [email("a@example.com")]);
    serve(G2, [email("b@example.com")]);
    expect(await eligible("a@example.com")).toBe(true);
    expect(calls).toEqual([`/access/groups/${G1}`]);
    calls = [];
    expect(await eligible("b@example.com")).toBe(true);
    expect(calls).toEqual([`/access/groups/${G1}`, `/access/groups/${G2}`]);
    calls = [];
    expect(await eligible("c@example.com")).toBe(false);
    expect(calls).toEqual([`/access/groups/${G1}`, `/access/groups/${G2}`]);
  });

  test("a failing group fetch is skipped and a later group grants", async () => {
    configure(`${G1}, ${G2}`);
    serve(G2, [email("a@example.com")]);
    const failures: Array<() => Response> = [
      () => new Response("forbidden", { status: 403 }),
      () => new Response("error", { status: 500 }),
      () => Response.json({ success: false, result: group(G1, [email("a@example.com")]) }),
      () => Response.json({ result: group(G1, [email("a@example.com")]) }),
      () => Response.json({ success: true, result: null }),
      () => new Response("not json", { status: 200 }),
      () => { throw new Error("network down"); },
    ];
    for (const failure of failures) {
      routes.set(`/access/groups/${G1}`, failure);
      calls = [];
      expect(await eligible("a@example.com")).toBe(true);
      expect(calls).toEqual([`/access/groups/${G1}`, `/access/groups/${G2}`]);
    }
  });

  test("a non-2xx response is not trusted even with a matching body", async () => {
    routes.set(`/access/groups/${G1}`, () => Response.json({ success: true, result: group(G1, [email("a@example.com")]) }, { status: 500 }));
    expect(await eligible("a@example.com")).toBe(false);
  });

  test("all fetches failing is not eligible", async () => {
    configure(`${G1},${G2},${G3}`);
    routes.set(`/access/groups/${G1}`, () => new Response("forbidden", { status: 403 }));
    routes.set(`/access/groups/${G2}`, () => { throw new Error("network down"); });
    expect(await eligible("a@example.com")).toBe(false);
    expect(calls).toHaveLength(3);
  });

  test("never throws, even with a broken environment", async () => {
    const broken = new Proxy({}, { get: () => { throw new Error("boom"); } }) as Env;
    expect(await isEmailEligible(broken, "a@example.com")).toBe(false);
    configure(G1);
    globalThis.fetch = (() => { throw new Error("sync failure"); }) as unknown as typeof fetch;
    expect(await eligible("a@example.com")).toBe(false);
  });
});

describe("ACCESS_GROUP_IDS", () => {
  test("empty or missing means nobody is eligible and nothing is fetched", async () => {
    serve(G1, [email("a@example.com")]);
    for (const value of ["", "   ", " , ,\n", undefined]) {
      env = { ...env, ACCESS_GROUP_IDS: value as string };
      expect(await eligible("a@example.com")).toBe(false);
    }
    const { ACCESS_GROUP_IDS: _removed, ...withoutVar } = env;
    expect(await isEmailEligible(withoutVar as Env, "a@example.com")).toBe(false);
    expect(calls).toHaveLength(0);
  });

  test("parses commas and whitespace, lowercases and dedupes", () => {
    expect(parseGroupIds(` ${G1.toUpperCase()},\n${G2}\t${G1} ,, ${G3} `)).toEqual([G1, G2, G3]);
  });

  test("accepts 32-hex and hyphenated UUID forms only; invalid entries are ignored with a warning", async () => {
    expect(parseGroupIds("abc, ../groups, g1, 1111111111111111111111111111111, 11111111-1111-1111-1111-11111111111g")).toEqual([]);
    expect(warnings.some((line) => line.includes("malformed"))).toBe(true);
    configure(`not-a-group ${G1} ${"z".repeat(32)}`);
    serve(G1, [email("a@example.com")]);
    expect(await eligible("a@example.com")).toBe(true);
    expect(calls).toEqual([`/access/groups/${G1}`]);
  });

  test("uses at most ten ids and warns about the rest", async () => {
    const ids = Array.from({ length: 12 }, (_, index) => index.toString(16).padStart(32, "a"));
    expect(new Set(ids).size).toBe(12);
    expect(parseGroupIds(ids.join(","))).toEqual(ids.slice(0, MAX_GROUP_IDS));
    expect(warnings.some((line) => line.includes("more than 10"))).toBe(true);
    configure(ids.join(" "));
    serve(ids[10] as string, [email("a@example.com")]);
    expect(await eligible("a@example.com")).toBe(false);
    expect(calls).toHaveLength(MAX_GROUP_IDS);
    expect(calls).not.toContain(`/access/groups/${ids[10]}`);
  });
});

describe("nothing is stored", () => {
  test("eligibility neither reads nor writes D1 and every call fetches live", async () => {
    const statements: string[] = [];
    env = { ...env, DB: new Proxy(env.DB, { get: (target, key) => { statements.push(String(key)); return Reflect.get(target, key); } }) };
    serve(G1, [email("a@example.com")]);
    expect(await eligible("a@example.com")).toBe(true);
    serve(G1, [email("b@example.com")]);
    expect(await eligible("a@example.com")).toBe(false);
    expect(await eligible("b@example.com")).toBe(true);
    expect(calls).toHaveLength(3);
    expect(statements).toEqual([]);
  });
});
