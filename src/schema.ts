// Mirrors the invitation table in migrations/0001_initial.sql; schema.test.ts keeps them aligned.
export const INVITATION_SCHEMA_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS invitation (
    id TEXT PRIMARY KEY NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL UNIQUE REFERENCES user(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    revoked_at INTEGER,
    created_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS invitation_status_idx
    ON invitation (used_at, revoked_at, expires_at)`,
];
