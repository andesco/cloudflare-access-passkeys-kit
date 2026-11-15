-- Self-service invitations and passkey recovery.

-- 'invite' registers the first passkey; 'recovery' replaces every existing passkey, session and
-- OAuth grant of the user, but only once the new passkey is stored.
ALTER TABLE "invitation" ADD COLUMN "kind" TEXT NOT NULL DEFAULT 'invite'
  CHECK ("kind" IN ('invite', 'recovery'));

-- The credential ID verified when a recovery link was consumed. The trigger below revokes the
-- user's old credentials only when exactly this credential is inserted, then clears it. Issuing a
-- new link and adding a passkey from a signed-in session also clear it.
ALTER TABLE "invitation" ADD COLUMN "pending_credential_id" TEXT;

-- Recovery revocation runs inside the passkey INSERT itself: if the insert fails, nothing is
-- revoked; if it succeeds, the old passkeys, sessions and OAuth grants are gone in the same
-- statement. Keep the body to plain DELETE and UPDATE statements with no comments, so the D1
-- migration statement splitter keeps the whole trigger as one statement.
CREATE TRIGGER IF NOT EXISTS "passkey_recovery_revoke"
AFTER INSERT ON "passkey"
WHEN EXISTS (
  SELECT 1 FROM "invitation"
  WHERE "invitation"."user_id" = NEW."userId"
    AND "invitation"."kind" = 'recovery'
    AND "invitation"."used_at" IS NOT NULL
    AND "invitation"."revoked_at" IS NULL
    AND "invitation"."pending_credential_id" = NEW."credentialID"
)
BEGIN
  DELETE FROM "oauthAccessToken" WHERE "userId" = NEW."userId";
  DELETE FROM "oauthRefreshToken" WHERE "userId" = NEW."userId";
  DELETE FROM "oauthConsent" WHERE "userId" = NEW."userId";
  DELETE FROM "session" WHERE "userId" = NEW."userId";
  DELETE FROM "passkey" WHERE "userId" = NEW."userId" AND "id" <> NEW."id";
  UPDATE "invitation" SET "pending_credential_id" = NULL WHERE "user_id" = NEW."userId";
END;

-- One row per requested address, keyed by an HMAC of the normalized address so the table never
-- holds the address itself. Claimed before the eligibility lookup for every address alike.
CREATE TABLE IF NOT EXISTS "request_cooldown" (
  "email_hash" TEXT NOT NULL PRIMARY KEY,
  "last_request_at" INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS "request_cooldown_last_request_at_idx" ON "request_cooldown" ("last_request_at");
