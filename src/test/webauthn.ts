// A software authenticator that produces "none"-attestation registration responses for tests.
type Cbor = number | string | Uint8Array | Map<Cbor, Cbor>;

function head(major: number, value: number): number[] {
  const type = major << 5;
  if (value < 24) return [type | value];
  if (value < 256) return [type | 24, value];
  return [type | 25, value >> 8, value & 255];
}

function cbor(value: Cbor): number[] {
  if (typeof value === "number") return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === "string") {
    const bytes = new TextEncoder().encode(value);
    return [...head(3, bytes.length), ...bytes];
  }
  if (value instanceof Uint8Array) return [...head(2, value.length), ...value];
  return [...head(5, value.size), ...[...value].flatMap(([key, item]) => [...cbor(key), ...cbor(item)])];
}

const base64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

export async function registrationResponse(options: {
  challenge: string;
  origin: string;
  rpId: string;
  userVerified?: boolean;
}) {
  const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
  const jwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
  const credentialId = crypto.getRandomValues(new Uint8Array(32));
  const coseKey = new Uint8Array(cbor(new Map<Cbor, Cbor>([
    [1, 2], [3, -7], [-1, 1],
    [-2, new Uint8Array(Buffer.from(jwk.x!, "base64url"))],
    [-3, new Uint8Array(Buffer.from(jwk.y!, "base64url"))],
  ])));
  const rpIdHash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(options.rpId)));
  const flags = options.userVerified === false ? 0x41 | 0x00 : 0x45; // UP + AT (+ UV)
  const authData = new Uint8Array([
    ...rpIdHash, flags, 0, 0, 0, 0,
    ...new Uint8Array(16),
    credentialId.length >> 8, credentialId.length & 255, ...credentialId,
    ...coseKey,
  ]);
  const attestationObject = new Uint8Array(cbor(new Map<Cbor, Cbor>([
    ["fmt", "none"], ["attStmt", new Map()], ["authData", authData],
  ])));
  const clientDataJSON = new TextEncoder().encode(JSON.stringify({
    type: "webauthn.create", challenge: options.challenge, origin: options.origin, crossOrigin: false,
  }));
  return {
    id: base64url(credentialId),
    rawId: base64url(credentialId),
    type: "public-key",
    clientExtensionResults: {},
    response: {
      attestationObject: base64url(attestationObject),
      clientDataJSON: base64url(clientDataJSON),
      transports: ["internal"],
    },
  };
}
