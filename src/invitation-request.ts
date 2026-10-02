import type { Auth } from "./auth";
import { accessPolicyAllowsEmail } from "./access-policy";
import { appName, requestOrigin } from "./constants";
import { cancelUnsentInvitation, issueInvitation } from "./invitations";
import { normalizeEmail } from "./validation";

const GENERIC_MESSAGE = "If authorized, we'll send an invitation email.";

function response(): Response {
  return Response.json({ message: GENERIC_MESSAGE }, {
    status: 202,
    headers: { "cache-control": "no-store" },
  });
}

const MAX_BODY_BYTES = 4096;

async function readBoundedText(request: Request): Promise<string | null> {
  const reader = request.body?.getReader();
  if (!reader) return null;
  const decoder = new TextDecoder();
  let text = "";
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_BODY_BYTES) {
      await reader.cancel();
      return null;
    }
    text += decoder.decode(value, { stream: true });
  }
  return text + decoder.decode();
}

export async function readRequest(
  request: Request,
): Promise<{ email: string; turnstileToken: string } | null> {
  if (!request.headers.get("content-type")?.includes("application/json")) return null;
  const text = await readBoundedText(request);
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
  const result = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    body,
  });
  if (!result.ok) return false;
  const value: unknown = await result.json();
  return Boolean(value && typeof value === "object" && "success" in value && value.success === true);
}

async function processRequest(request: Request, env: Env, getAuth: () => Auth, email: string): Promise<void> {
  try {
    if (!(await accessPolicyAllowsEmail(env, email))) return;
    const invitation = await issueInvitation(getAuth(), env.DB, email, 7);
    if (!invitation) return;
    const url = `${requestOrigin(env, request)}/invite/${invitation.token}`;
    const name = appName(env);
    try {
      const result = await env.EMAIL.send({
        to: email,
        from: { name, email: env.INVITATION_FROM },
        subject: `Your ${name} invitation`,
        text: `You have been invited to register a passkey.\n\nOpen this single-use link within 7 days:\n${url}\n\nIf you did not request this invitation, you can ignore this email.`,
        html: `<p>You have been invited to register a passkey.</p><p><a href="${url}">Create your passkey</a></p><p>This single-use link expires in 7 days. If you did not request it, you can ignore this email.</p>`,
      });
      console.log(JSON.stringify({
        message: "invitation email accepted",
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
          error: rollbackError instanceof Error ? rollbackError.message : String(rollbackError),
        }));
      }
      throw error;
    }
  } catch (error) {
    console.error(JSON.stringify({
      message: "invitation request processing failed",
      error: error instanceof Error ? error.message : String(error),
    }));
  }
}

export async function handleInvitationRequest(
  request: Request,
  env: Env,
  getAuth: () => Auth,
  ctx: ExecutionContext,
): Promise<Response> {
  if (request.method !== "POST") return new Response("Method not allowed", { status: 405 });

  // Rate-limit before reading the body or doing any other work.
  const ip = request.headers.get("cf-connecting-ip") ?? "unknown";
  const rate = await env.INVITE_RATE_LIMITER.limit({ key: ip });
  if (!rate.success) return response();

  const input = await readRequest(request);
  if (!input) return response();

  if (env.TURNSTILE_ENABLED === "true" &&
      (!input.turnstileToken || !(await verifyTurnstile(env, input.turnstileToken, request)))) {
    return response();
  }

  ctx.waitUntil(processRequest(request, env, getAuth, input.email));
  return response();
}
