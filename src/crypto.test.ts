import { describe, expect, test } from "bun:test";
import { hmacSha256Hex, randomToken, sha256Hex } from "./crypto";

describe("auth cryptography helpers", () => {
  test("hashes values with SHA-256", async () => {
    expect(await sha256Hex("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  test("computes HMAC-SHA256 as hex (RFC 4231 test case 2)", async () => {
    expect(await hmacSha256Hex("Jefe", "what do ya want for nothing?")).toBe(
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    );
  });

  test("creates URL-safe 256-bit invitation tokens", () => {
    const first = randomToken();
    const second = randomToken();
    expect(first).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(second).not.toBe(first);
  });
});
