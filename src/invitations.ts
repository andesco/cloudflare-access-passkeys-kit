import { APIError } from "better-auth/api";
import { randomToken, sha256Hex } from "./crypto";

/**
 * The invitation token travels in this header, never in a URL: the emailed link keeps it in the
 * fragment (which browsers do not send), and the client copies it into the header on every request.
 */
export const INVITATION_HEADER = "x-invitation-token";

/** 'invite' registers a first passkey; 'recovery' replaces every existing one once completed. */
export type InvitationKind = "invite" | "recovery";

export const INVITATION_DAYS = 7;
export const RECOVERY_DAYS = 1;

export function invitationToken(ctx: { headers?: Headers } | null | undefined): string | null {
  return ctx?.headers?.get(INVITATION_HEADER) || null;
}

export interface InvitationRow {
  id: string;
  email: string;
  user_id: string;
  kind: InvitationKind;
  expires_at: number;
  used_at: number | null;
  revoked_at: number | null;
  created_at: number;
}

const COLUMNS = "id, email, user_id, kind, expires_at, used_at, revoked_at, created_at";

export async function resolveInvitation(
  db: D1Database,
  token: string | null | undefined,
): Promise<InvitationRow> {
  if (!token) {
    throw new APIError("FORBIDDEN", { message: "A valid invitation is required" });
  }

  const tokenHash = await sha256Hex(token);
  const invitation = await db
    .prepare(
      `SELECT ${COLUMNS}
       FROM invitation
       WHERE token_hash = ?1
         AND used_at IS NULL
         AND revoked_at IS NULL
         AND expires_at > ?2`,
    )
    .bind(tokenHash, Date.now())
    .first<InvitationRow>();

  if (!invitation) {
    throw new APIError("FORBIDDEN", { message: "This invitation is invalid or expired" });
  }

  return invitation;
}

export async function consumeInvitation(db: D1Database, token: string): Promise<InvitationRow> {
  const tokenHash = await sha256Hex(token);
  const invitation = await db
    .prepare(
      `UPDATE invitation
       SET used_at = ?1
       WHERE token_hash = ?2
         AND used_at IS NULL
         AND revoked_at IS NULL
         AND expires_at > ?1
       RETURNING ${COLUMNS}`,
    )
    .bind(Date.now(), tokenHash)
    .first<InvitationRow>();

  if (!invitation) {
    throw new APIError("FORBIDDEN", { message: "This invitation has already been used" });
  }

  return invitation;
}

/**
 * Consumes the invitation for a verified passkey registration of `userId` and, for a recovery link,
 * records `credentialId` as the one credential allowed to complete it. Nothing is revoked here: the
 * `passkey_recovery_revoke` trigger (migration 0005) deletes the user's other passkeys, sessions,
 * OAuth tokens and consents inside the INSERT that stores exactly this credential. If that insert
 * never happens, the user keeps everything and must request a new link.
 */
export async function completeInvitation(
  db: D1Database,
  token: string,
  userId: string,
  credentialId: string,
): Promise<InvitationRow> {
  const pending = await resolveInvitation(db, token);
  if (pending.user_id !== userId) {
    throw new APIError("FORBIDDEN", { message: "Invitation does not match this user" });
  }
  if (!credentialId) {
    throw new APIError("BAD_REQUEST", { message: "A verified credential is required" });
  }

  const now = Date.now();
  const consumed = await db.prepare(
    `UPDATE invitation
     SET used_at = ?3,
         pending_credential_id = CASE WHEN kind = 'recovery' THEN ?4 ELSE NULL END
     WHERE token_hash = ?2 AND user_id = ?1
       AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?3`,
  ).bind(userId, await sha256Hex(token), now, credentialId).run();

  if ((consumed.meta?.changes ?? 0) !== 1) {
    throw new APIError("FORBIDDEN", { message: "This invitation has already been used" });
  }
  return { ...pending, used_at: now };
}

/**
 * Forgets any recovery credential still pending for `userId`, so a passkey added from a signed-in
 * session can never complete an earlier recovery whose passkey insert failed.
 */
export async function clearPendingRecovery(db: D1Database, userId: string): Promise<void> {
  await db.prepare(
    "UPDATE invitation SET pending_credential_id = NULL WHERE user_id = ?1 AND pending_credential_id IS NOT NULL",
  ).bind(userId).run();
}

export async function invitationRegistrationComplete(db: D1Database, token: string): Promise<boolean> {
  if (!token) return false;
  const result = await db.prepare(
    `SELECT p.id
     FROM invitation i
     INNER JOIN passkey p ON p.userId = i.user_id
     WHERE i.token_hash = ?1 AND i.used_at IS NOT NULL AND i.pending_credential_id IS NULL
     LIMIT 1`,
  ).bind(await sha256Hex(token)).first<{ id: string }>();
  return Boolean(result);
}

/** Creates or resets the single invitation row for a user. */
export function upsertInvitation(
  db: D1Database,
  invitation: {
    id: string;
    tokenHash: string;
    email: string;
    userId: string;
    kind: InvitationKind;
    expiresAt: number;
    createdAt: number;
  },
): D1PreparedStatement {
  return db.prepare(
    `INSERT INTO invitation
      (id, token_hash, email, user_id, kind, expires_at, used_at, revoked_at, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL, ?7)
     ON CONFLICT(user_id) DO UPDATE SET
       token_hash = excluded.token_hash,
       email = excluded.email,
       kind = excluded.kind,
       expires_at = excluded.expires_at,
       used_at = NULL,
       revoked_at = NULL,
       pending_credential_id = NULL,
       created_at = excluded.created_at
     RETURNING id`,
  ).bind(
    invitation.id,
    invitation.tokenHash,
    invitation.email,
    invitation.userId,
    invitation.kind,
    invitation.expiresAt,
    invitation.createdAt,
  );
}

export interface IssuedInvitation {
  id: string;
  token: string;
  kind: InvitationKind;
  userId: string;
  /** True when this call created the user row, so a failed send can remove it again. */
  createdUser: boolean;
  validDays: number;
  expiresAt: number;
  createdAt: number;
}

/**
 * Issues a link for an address the caller has already found eligible: an invitation when the user
 * does not exist or has no passkey, otherwise a recovery link. Nothing existing is revoked here;
 * recovery only takes effect when its new passkey is stored. Rate limiting is the caller's job.
 */
export async function issueInvitation(db: D1Database, email: string): Promise<IssuedInvitation> {
  let user = await db.prepare('SELECT id FROM "user" WHERE email = ?1').bind(email).first<{ id: string }>();
  let createdUser = false;
  if (!user) {
    const iso = new Date().toISOString();
    // Same shape Better Auth's createUser writes: ISO-8601 dates, verified because the link proves it.
    user = await db.prepare(
      `INSERT INTO "user" (id, name, email, emailVerified, image, createdAt, updatedAt)
       VALUES (?1, ?2, ?2, 1, NULL, ?3, ?3)
       ON CONFLICT(email) DO NOTHING
       RETURNING id`,
    ).bind(crypto.randomUUID(), email, iso).first<{ id: string }>();
    if (user) createdUser = true;
    else user = await db.prepare('SELECT id FROM "user" WHERE email = ?1').bind(email).first<{ id: string }>();
    if (!user) throw new Error("User creation returned no record");
  }
  const userId = user.id;

  const passkey = await db.prepare("SELECT id FROM passkey WHERE userId = ?1 LIMIT 1")
    .bind(userId).first<{ id: string }>();
  const kind: InvitationKind = passkey ? "recovery" : "invite";
  const validDays = kind === "recovery" ? RECOVERY_DAYS : INVITATION_DAYS;

  const token = randomToken();
  const now = Date.now();
  const expiresAt = now + validDays * 86_400_000;
  try {
    const invitation = await upsertInvitation(db, {
      id: crypto.randomUUID(),
      tokenHash: await sha256Hex(token),
      email,
      userId,
      kind,
      expiresAt,
      createdAt: now,
    }).first<{ id: string }>();
    if (!invitation) throw new Error("Invitation creation returned no record");
    return { id: invitation.id, token, kind, userId, createdUser, validDays, expiresAt, createdAt: now };
  } catch (error) {
    if (createdUser) await deleteUserWithoutPasskey(db, userId);
    throw error;
  }
}

function deleteUserWithoutPasskey(db: D1Database, userId: string) {
  return db.prepare(
    `DELETE FROM "user" WHERE id = ?1 AND NOT EXISTS (SELECT 1 FROM passkey WHERE userId = ?1)`,
  ).bind(userId).run();
}

/** Withdraws a link whose email was never accepted, and the user row if this request created it. */
export async function cancelUnsentInvitation(
  db: D1Database,
  invitation: Pick<IssuedInvitation, "id" | "createdAt" | "userId" | "createdUser">,
): Promise<void> {
  await db.prepare(
    "DELETE FROM invitation WHERE id = ?1 AND created_at = ?2 AND used_at IS NULL",
  ).bind(invitation.id, invitation.createdAt).run();
  if (invitation.createdUser) await deleteUserWithoutPasskey(db, invitation.userId);
}
