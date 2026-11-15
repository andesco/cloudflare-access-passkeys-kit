import * as accessGroups from "./access-groups";
import { requestOrigin } from "./constants";
import { hmacSha256Hex } from "./crypto";
import { readBoundedText } from "./http";
import { cancelUnsentInvitation, issueInvitation } from "./invitations";
import { sendLinkMail } from "./mail";
import { normalizeEmail } from "./validation";

const GENERIC_MESSAGE = "If this address is eligible, we'll email it a link.";
const MAX_BODY_BYTES = 4096;

/** One request per address in this window, whether or not the address is eligible. */
export const REQUEST_COOLDOWN_MS = 600_000;

/**
 * Indirection for the eligibility check so tests can replace it without mocking the module.
 * Namespace access also keeps this file loadable while access-groups.ts is mid-change.
 */
export const eligibility = {
  isEmailEligible: (env: Env, email: string): Promise<boolean> => accessGroups.isEmailEligible(env, email),
};

function accepted(): Response {
  return Response.json({ message: GENERIC_MESSAGE }, {
    status: 202,
    headers: { "cache-control": "no-store" },
  });
}

export async function readRequest(
  request: Request,
): Promise<{ email: string; turnstileToken: string } | null> {
  if (!request.headers.get("content-type")?.includes("application/json")) return null;
  const text = await readBoundedText(request, MAX_BODY_BYTES);
  if (text === null) return null;
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return null;
  }
  if (!body || typeof body !== "object") return null;
  const value = body as Record<string, unknown>;
  const email = normalizeEmail(value.email);
  if (!email) return null;
  return { email, turnstileToken: typeof value.turnstileToken === "string" ? value.turnstileToken : "" };
}

async function verifyTurnstile(env: Env, token: string, request: Request): Promise<boolean> {
  if (!env.TURNSTILE_SECRET_KEY) {
    console.error(JSON.stringify({ message: "TURNSTILE_ENABLED is true but TURNSTILE_SECRET_KEY is not set" }));
    return false;
  }
  const body = new URLSearchParams({ secret: env.TURNSTILE_SECRET_KEY, response: token });
  const remoteIp = request.headers.get("cf-connecting-ip");
  if (remoteIp) body.set("remoteip", remoteIp);
  try {
    const result = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body,
    });
    if (!result.ok) return false;
    const value: unknown = await result.json();
    return Boolean(value && typeof value === "object" && "success" in value && value.success === true);
  } catch {
    return false;
  }
}

/**
 * The form of an address used only for the cooldown key: trimmed, lowercased, and without a
 * `+tag` in the local part, so `victim+1@d` and `victim+2@d` share one slot. Dots are kept.
 * Eligibility, the user row and delivery all use the address as requested.
 */
export function cooldownCanonicalEmail(email: string): string {
  const normalized = email.trim().toLowerCase();
  const at = normalized.lastIndexOf("@");
  if (at < 0) return normalized;
  const local = normalized.slice(0, at);
  const plus = local.indexOf("+");
  return plus < 0 ? normalized : `${local.slice(0, plus)}${normalized.slice(at)}`;
}

export function requestCooldownKey(env: Env, email: string): Promise<string> {
  return hmacSha256Hex(env.BETTER_AUTH_SECRET, cooldownCanonicalEmail(email));
}

/**
 * Atomically claims the address's request slot. Returns false when the address was claimed within
 * the cooldown window. A claim is never released, even when the email later fails to send.
 */
export async function claimRequestCooldown(env: Env, email: string, now = Date.now()): Promise<boolean> {
  const claimed = await env.DB.prepare(
    `INSERT INTO request_cooldown (email_hash, last_request_at) VALUES (?1, ?2)
     ON CONFLICT(email_hash) DO UPDATE SET last_request_at = excluded.last_request_at
       WHERE request_cooldown.last_request_at <= ?3
     RETURNING email_hash`,
  ).bind(await requestCooldownKey(env, email), now, now - REQUEST_COOLDOWN_MS).first<{ email_hash: string }>();
  return claimed !== null;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Everything that depends on the address. Runs after the response is decided; never throws. */
async function processRequest(env: Env, origin: string, email: string): Promise<void> {
  try {
    if (!(await claimRequestCooldown(env, email))) return;
    if (!(await eligibility.isEmailEligible(env, email))) return;

    const invitation = await issueInvitation(env.DB, email);
    const url = `${origin}/invite#${invitation.token}`;
    try {
      const result = await sendLinkMail(env, invitation.kind, email, url, invitation.validDays);
      console.log(JSON.stringify({
        message: "invitation email accepted",
        kind: invitation.kind,
        invitationId: invitation.id,
        messageId: result.messageId,
      }));
    } catch (error) {
      try {
        await cancelUnsentInvitation(env.DB, invitation);
      } catch (rollbackError) {
        console.error(JSON.stringify({
          message: "failed to cancel unsent invitation",
          invitationId: invitation.id,
          error: errorMessage(rollbackError),
        }));
      }
      throw error;
    }
  } catch (error) {
    // Never log the address; the error text comes from D1, the policy lookup or the mail binding.
    console.error(JSON.stringify({
      message: "invitation request processing failed",
      error: errorMessage(error).replaceAll(email, "[redacted]"),
    }));
  }
}

/**
 * POST /api/invitations/request. The response depends only on the rate limit and the request's
 * shape, never on the address: eligible, ineligible, known, cooling down or failing to send all
 * get the same 202, and all address-dependent work runs in `ctx.waitUntil` afterwards.
 */
export async function handleInvitationRequest(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  if (request.method !== "POST") {
    return new Response("Method not allowed", { status: 405, headers: { allow: "POST" } });
  }

  // Rate-limit per IP before reading the body or doing any other work.
  const ip = request.headers.get("cf-connecting-ip") ?? "unknown";
  const rate = await env.INVITE_RATE_LIMITER.limit({ key: ip });
  if (!rate.success) {
    return Response.json({ error: "Too many requests" }, {
      status: 429,
      headers: { "cache-control": "no-store", "retry-after": "60" },
    });
  }

  const input = await readRequest(request);
  if (!input) {
    return Response.json({ error: "A valid email address is required" }, {
      status: 400,
      headers: { "cache-control": "no-store" },
    });
  }

  // Turnstile depends only on the token, never on the address, so it may fail before the 202.
  // Everything address-dependent stays in ctx.waitUntil below.
  if (env.TURNSTILE_ENABLED === "true" &&
      (!input.turnstileToken || !(await verifyTurnstile(env, input.turnstileToken, request)))) {
    return Response.json({ error: "Verification failed" }, {
      status: 403,
      headers: { "cache-control": "no-store" },
    });
  }

  ctx.waitUntil(processRequest(env, requestOrigin(env, request), input.email));
  return accepted();
}
