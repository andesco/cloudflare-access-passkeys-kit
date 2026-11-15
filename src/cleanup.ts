const DAY_MS = 86_400_000;
const ORPHAN_GRACE_DAYS = 30;

export interface CleanupResult {
  expiredVerifications: number;
  expiredSessions: number;
  expiredAccessTokens: number;
  expiredRefreshTokens: number;
  /** Rows changed by the user delete; may include cascaded invitation rows depending on the driver. */
  abandonedUsers: number;
  expiredCooldowns: number;
}

// Better Auth stores dates as ISO-8601 text. The typeof guard keeps an unexpected storage format
// from ever matching, because SQLite orders every INTEGER before every TEXT value.
const expiredBefore = (table: string) =>
  `DELETE FROM ${table} WHERE typeof("expiresAt") = 'text' AND "expiresAt" < ?1`;

/**
 * Deletes rows nothing else removes: expired challenges, sessions and OAuth tokens, plus users without
 * a passkey whose invitation expired unused (or was revoked), was consumed more than the grace period
 * ago, or who have no invitation at all and were created more than the grace period ago.
 * The user delete cascades to the invitation row. A user with a passkey is never deleted here, and
 * eligibility is never consulted: losing eligibility only stops new invitation and recovery links.
 * Request cooldown rows older than a day are removed too.
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
         AND (
           EXISTS (
             SELECT 1 FROM "invitation"
             WHERE "invitation"."user_id" = "user"."id"
               AND (
                 ("invitation"."expires_at" < ?1
                   AND ("invitation"."used_at" IS NULL OR "invitation"."revoked_at" IS NOT NULL))
                 OR ("invitation"."used_at" IS NOT NULL AND "invitation"."used_at" < ?1)
               )
           )
           OR (
             NOT EXISTS (SELECT 1 FROM "invitation" WHERE "invitation"."user_id" = "user"."id")
             AND typeof("user"."createdAt") = 'text' AND "user"."createdAt" < ?2
           )
         )`,
    ).bind(orphanCutoff, new Date(orphanCutoff).toISOString()),
    db.prepare(`DELETE FROM "request_cooldown" WHERE "last_request_at" < ?1`).bind(now - DAY_MS),
  ]);
  const changes = results.map((result) => result.meta?.changes ?? 0);
  return {
    expiredVerifications: changes[0]!,
    expiredSessions: changes[1]!,
    expiredAccessTokens: changes[2]!,
    expiredRefreshTokens: changes[3]!,
    abandonedUsers: changes[4]!,
    expiredCooldowns: changes[5]!,
  };
}
