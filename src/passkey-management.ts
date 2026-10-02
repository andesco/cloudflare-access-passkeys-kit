import { APIError, createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
import { appName } from "./constants";

/** How recently the user must have signed in with a passkey to add or remove one. */
export const RECENT_SIGN_IN_MS = 5 * 60_000;
export const MAX_PASSKEYS = 10;
export const MAX_PASSKEY_NAME_LENGTH = 64;
// The browser client matches this text to offer a passkey re-confirmation.
export const RECENT_SIGN_IN_MESSAGE = "Recent sign-in required";

type PasskeyChange = "added" | "removed";

/** Sessions are created at passkey sign-in and never re-created, so createdAt is the last verification. */
export function isRecentSignIn(createdAt: Date | string | number, now = Date.now()): boolean {
  const signedInAt = new Date(createdAt).getTime();
  return Number.isFinite(signedInAt) && now - signedInAt <= RECENT_SIGN_IN_MS;
}

function assertRecentSignIn(sessionCreatedAt: Date | string | number, now: number): void {
  if (!isRecentSignIn(sessionCreatedAt, now)) {
    throw new APIError("FORBIDDEN", { message: RECENT_SIGN_IN_MESSAGE });
  }
}

export function assertCanAddPasskey(
  input: { sessionCreatedAt: Date | string | number; passkeyCount: number },
  now = Date.now(),
): void {
  assertRecentSignIn(input.sessionCreatedAt, now);
  if (input.passkeyCount >= MAX_PASSKEYS) {
    throw new APIError("BAD_REQUEST", { message: `A maximum of ${MAX_PASSKEYS} passkeys is allowed` });
  }
}

export function assertCanRemovePasskey(
  input: { sessionCreatedAt: Date | string | number; passkeyCount: number },
  now = Date.now(),
): void {
  assertRecentSignIn(input.sessionCreatedAt, now);
  if (input.passkeyCount <= 1) {
    throw new APIError("BAD_REQUEST", { message: "You cannot remove your only passkey" });
  }
}

export async function notifyPasskeyChange(env: Env, email: string, change: PasskeyChange): Promise<void> {
  const name = appName(env);
  const text = `A passkey was ${change} ${change === "added" ? "to" : "from"} your ${name} account.\n\nIf this was not you, contact the administrator to recover your account.`;
  try {
    await env.EMAIL.send({
      to: email,
      from: { name, email: env.INVITATION_FROM },
      subject: `A passkey was ${change} on your ${name} account`,
      text,
      html: `<p>${text.replace("\n\n", "</p><p>")}</p>`,
    });
  } catch (error) {
    console.error(JSON.stringify({
      message: "passkey change notification failed",
      error: error instanceof Error ? error.message : String(error),
    }));
  }
}

/** Guards for Better Auth's built-in delete and rename endpoints, which only check ownership. */
export function passkeyManagementHook(env: Env) {
  return createAuthMiddleware(async (ctx) => {
    if (ctx.path !== "/passkey/delete-passkey" && ctx.path !== "/passkey/update-passkey") return;
    const session = await getSessionFromCtx(ctx);
    if (!session) return; // the endpoint's own session middleware rejects this

    if (ctx.path === "/passkey/update-passkey") {
      const name = (ctx.body as { name?: unknown } | undefined)?.name;
      if (typeof name === "string" && name.trim().length > MAX_PASSKEY_NAME_LENGTH) {
        throw new APIError("BAD_REQUEST", { message: `Names are limited to ${MAX_PASSKEY_NAME_LENGTH} characters` });
      }
      return;
    }

    const passkeys = await ctx.context.adapter.findMany({
      model: "passkey",
      where: [{ field: "userId", value: session.user.id }],
    });
    assertCanRemovePasskey({ sessionCreatedAt: session.session.createdAt, passkeyCount: passkeys.length });
    await notifyPasskeyChange(env, session.user.email, "removed");
  });
}
