const DAY_MS = 86_400_000;
const ORPHAN_GRACE_DAYS = 30;

export interface CleanupResult {
  expiredVerifications: number;
  expiredSessions: number;
  expiredAccessTokens: number;
  expiredRefreshTokens: number;
  /** Rows changed by the user delete; may include cascaded invitation rows depending on the driver. */
  abandonedUsers: number;
}

// Better Auth stores dates as ISO-8601 text. The typeof guard keeps an unexpected storage format
// from ever matching, because SQLite orders every INTEGER before every TEXT value.
const expiredBefore = (table: string) =>
  `DELETE FROM ${table} WHERE typeof("expiresAt") = 'text' AND "expiresAt" < ?1`;

/**
 * Deletes rows nothing else removes: expired challenges, sessions and OAuth tokens, plus users who were
 * created for an invitation that expired unused (or was revoked) and never registered a passkey.
 * The user delete cascades to the invitation row.
 */
export async function cleanup(db: D1Database, now = Date.now()): Promise<CleanupResult> {
  const iso = new Date(now).toISOString();
  const orphanCutoff = now - ORPHAN_GRACE_DAYS * DAY_MS;
  const results = await db.batch([
    db.prepare(expiredBefore('"verification"')).bind(iso),
    db.prepare(expiredBefore('"session"')).bind(iso),
    db.prepare(expiredBefore('"oauthAccessToken"')).bind(iso),
    db.prepare(expiredBefore('"oauthRefreshToken"')).bind(iso),
    db.prepare(
      `DELETE FROM "user"
       WHERE NOT EXISTS (SELECT 1 FROM "passkey" WHERE "passkey"."userId" = "user"."id")
         AND EXISTS (
           SELECT 1 FROM "invitation"
           WHERE "invitation"."user_id" = "user"."id"
             AND "invitation"."expires_at" < ?1
             AND ("invitation"."used_at" IS NULL OR "invitation"."revoked_at" IS NOT NULL)
         )`,
    ).bind(orphanCutoff),
  ]);
  const changes = results.map((result) => result.meta?.changes ?? 0);
  return {
    expiredVerifications: changes[0]!,
    expiredSessions: changes[1]!,
    expiredAccessTokens: changes[2]!,
    expiredRefreshTokens: changes[3]!,
    abandonedUsers: changes[4]!,
  };
}
