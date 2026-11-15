const encoder = new TextEncoder();

export async function sha256(value: string): Promise<ArrayBuffer> {
  return crypto.subtle.digest("SHA-256", encoder.encode(value));
}

export async function sha256Hex(value: string): Promise<string> {
  return hex(new Uint8Array(await sha256(value)));
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** HMAC-SHA256 of `value` keyed by `key`, as lowercase hex. */
export async function hmacSha256Hex(key: string, value: string): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return hex(new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(value))));
}

export function randomToken(bytes = 32): string {
  const value = new Uint8Array(bytes);
  crypto.getRandomValues(value);
  return btoa(String.fromCharCode(...value))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}
