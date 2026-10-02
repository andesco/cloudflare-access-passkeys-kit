import { oauthProvider } from "@better-auth/oauth-provider";
import { passkey } from "@better-auth/passkey";
import { betterAuth } from "better-auth";
import { APIError, getSessionFromCtx } from "better-auth/api";
import { jwt } from "better-auth/plugins";
import { appName, requestOrigin } from "./constants";
import { consumeInvitation, invitationToken, resolveInvitation } from "./invitations";
import { assertCanAddPasskey, notifyPasskeyChange, passkeyManagementHook } from "./passkey-management";

/** `database` overrides the Better Auth adapter handle; tests pass raw SQLite while `env.DB` stays a D1 stand-in. */
export function createAuth(env: Env, request: Request, database: unknown = env.DB) {
  const origin = requestOrigin(env, request);
  const rpID = new URL(origin).hostname;
  const name = appName(env);

  return betterAuth({
    appName: name,
    baseURL: origin,
    secret: env.BETTER_AUTH_SECRET,
    database: database as D1Database,
    trustedOrigins: [origin],
    emailAndPassword: { enabled: false },
    hooks: { before: passkeyManagementHook(env) },
    advanced: {
      database: { generateId: "uuid" },
      useSecureCookies: true,
    },
    plugins: [
      jwt({
        jwks: {
          keyPairConfig: { alg: "RS256", modulusLength: 2048 },
        },
        disableSettingJwtHeader: true,
      }),
      passkey({
        rpID,
        rpName: name,
        origin,
        authenticatorSelection: {
          residentKey: "required",
          requireResidentKey: true,
          userVerification: "required",
        },
        registration: {
          requireSession: false,
          resolveUser: async ({ ctx }) => {
            const invitation = await resolveInvitation(env.DB, invitationToken(ctx));
            return {
              id: invitation.user_id,
              name: invitation.email,
              displayName: invitation.email,
            };
          },
          afterVerification: async ({ ctx, verification, user }) => {
            const token = invitationToken(ctx);
            if (!verification.registrationInfo?.userVerified) {
              throw new APIError("UNAUTHORIZED", { message: "User verification is required" });
            }
            if (!token) {
              // No invitation: only a signed-in user may add another passkey to their own account.
              const session = await getSessionFromCtx(ctx);
              if (!session || session.user.id !== user.id) {
                throw new APIError("FORBIDDEN", { message: "A valid invitation is required" });
              }
              const passkeys = await ctx.context.adapter.findMany({
                model: "passkey",
                where: [{ field: "userId", value: user.id }],
              });
              assertCanAddPasskey({
                sessionCreatedAt: session.session.createdAt,
                passkeyCount: passkeys.length,
              });
              await notifyPasskeyChange(env, session.user.email, "added");
              return { name: session.user.email };
            }
            // Validate ownership before consuming so a mismatched invitation is not burned.
            const pending = await resolveInvitation(env.DB, token);
            if (pending.user_id !== user.id) {
              throw new APIError("FORBIDDEN", { message: "Invitation does not match this user" });
            }
            const invitation = await consumeInvitation(env.DB, token);
            return { name: invitation.email };
          },
        },
        authentication: {
          afterVerification: ({ verification }) => {
            if (!verification.authenticationInfo.userVerified) {
              throw new APIError("UNAUTHORIZED", { message: "User verification is required" });
            }
          },
        },
      }),
      oauthProvider({
        loginPage: "/",
        consentPage: "/consent",
        scopes: ["openid", "email", "profile"],
        grantTypes: ["authorization_code"],
        allowDynamicClientRegistration: false,
        allowUnauthenticatedClientRegistration: false,
        silenceWarnings: {
          oauthAuthServerConfig: true,
          openidConfig: true,
        },
        clientReference: ({ user }) => user?.email.startsWith("_system.")
          ? "cloudflare-access"
          : undefined,
        clientPrivileges: ({ user }) => user?.email.startsWith("_system.") ?? false,
      }),
    ],
  });
}

export type Auth = ReturnType<typeof createAuth>;
