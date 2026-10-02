import { APIError } from "better-auth/api";
import { randomToken, sha256Hex } from "./crypto";
import type { Auth } from "./auth";

export interface InvitationRow {
  id: string;
  email: string;
  user_id: string;
  expires_at: number;
  used_at: number | null;
  revoked_at: number | null;
  created_at: number;
}

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
      `SELECT id, email, user_id, expires_at, used_at, revoked_at, created_at
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
       RETURNING id, email, user_id, expires_at, used_at, revoked_at, created_at`,
    )
    .bind(Date.now(), tokenHash)
    .first<InvitationRow>();

  if (!invitation) {
    throw new APIError("FORBIDDEN", { message: "This invitation has already been used" });
  }

  return invitation;
}

export async function invitationRegistrationComplete(db: D1Database, token: string): Promise<boolean> {
  if (!token) return false;
  const result = await db.prepare(
    `SELECT p.id
     FROM invitation i
     INNER JOIN passkey p ON p.userId = i.user_id
     WHERE i.token_hash = ?1 AND i.used_at IS NOT NULL
     LIMIT 1`,
  ).bind(await sha256Hex(token)).first<{ id: string }>();
  return Boolean(result);
}

/** Creates or resets the single invitation row for a user. Shared by email requests and CLI recovery. */
export function upsertInvitation(
  db: D1Database,
  invitation: {
    id: string;
    tokenHash: string;
    email: string;
    userId: string;
    expiresAt: number;
    createdAt: number;
  },
): D1PreparedStatement {
  return db.prepare(
    `INSERT INTO invitation
      (id, token_hash, email, user_id, expires_at, used_at, revoked_at, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, ?6)
     ON CONFLICT(user_id) DO UPDATE SET
       token_hash = excluded.token_hash,
       email = excluded.email,
       expires_at = excluded.expires_at,
       used_at = NULL,
       revoked_at = NULL,
       created_at = excluded.created_at
     RETURNING id`,
  ).bind(
    invitation.id,
    invitation.tokenHash,
    invitation.email,
    invitation.userId,
    invitation.expiresAt,
    invitation.createdAt,
  );
}

export async function issueInvitation(
  auth: Auth,
  db: D1Database,
  email: string,
  days: number,
): Promise<{ id: string; token: string; expiresAt: number; createdAt: number } | null> {
  const context = await auth.$context;
  const existing = await context.internalAdapter.findUserByEmail(email, { includeAccounts: false });
  let user = existing?.user;
  if (user) {
    const passkey = await db.prepare("SELECT id FROM passkey WHERE userId = ?1 LIMIT 1")
      .bind(user.id).first<{ id: string }>();
    if (passkey) return null;
    const recent = await db.prepare(
      "SELECT id FROM invitation WHERE user_id = ?1 AND created_at > ?2 LIMIT 1",
    ).bind(user.id, Date.now() - 600_000).first<{ id: string }>();
    if (recent) return null;
  } else {
    user = await context.internalAdapter.createUser({ email, name: email, emailVerified: true });
  }

  const token = randomToken();
  const now = Date.now();
  const expiresAt = now + days * 86_400_000;
  try {
    const invitation = await upsertInvitation(db, {
      id: crypto.randomUUID(),
      tokenHash: await sha256Hex(token),
      email,
      userId: user.id,
      expiresAt,
      createdAt: now,
    }).first<{ id: string }>();
    if (!invitation) throw new Error("Invitation creation returned no record");
    return { id: invitation.id, token, expiresAt, createdAt: now };
  } catch (error) {
    if (!existing) await context.internalAdapter.deleteUser(user.id);
    throw error;
  }
}

export async function cancelUnsentInvitation(
  db: D1Database,
  invitation: { id: string; createdAt: number },
): Promise<void> {
  await db.prepare(
    "DELETE FROM invitation WHERE id = ?1 AND created_at = ?2 AND used_at IS NULL",
  ).bind(invitation.id, invitation.createdAt).run();
}
