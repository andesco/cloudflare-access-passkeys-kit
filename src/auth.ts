import { oauthProvider } from "@better-auth/oauth-provider";
import { passkey } from "@better-auth/passkey";
import { betterAuth } from "better-auth";
import { APIError, getSessionFromCtx } from "better-auth/api";
import { jwt } from "better-auth/plugins";
import { appName, requestOrigin } from "./constants";
import { clearPendingRecovery, completeInvitation, invitationToken, resolveInvitation } from "./invitations";
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
            const registrationInfo = verification.registrationInfo;
            if (!registrationInfo?.userVerified) {
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
              // A credential left pending by a failed recovery must never revoke anything later.
              await clearPendingRecovery(env.DB, user.id);
              await notifyPasskeyChange(env, session.user.email, "added");
              return { name: session.user.email };
            }
            // Validates ownership before consuming, so a mismatched invitation is not burned. For a
            // recovery link this only records the verified credential ID; the database trigger
            // revokes the old passkeys, sessions and OAuth grants in the same statement that stores
            // this credential, so a failed insert revokes nothing.
            const invitation = await completeInvitation(env.DB, token, user.id, registrationInfo.credential.id);
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
        // No user may create, read or change OAuth clients over HTTP; clients are provisioned
        // directly in the database.
        clientPrivileges: () => false,
      }),
    ],
  });
}

export type Auth = ReturnType<typeof createAuth>;
