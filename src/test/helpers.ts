import { Database } from "bun:sqlite";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createAuth } from "../auth";

class Statement {
  constructor(
    private readonly db: Database,
    private readonly sql: string,
    private readonly params: unknown[] = [],
  ) {}

  bind(...params: unknown[]): Statement {
    return new Statement(this.db, this.sql, params);
  }

  async first<T>(): Promise<T | null> {
    return (this.db.prepare(this.sql).get(...(this.params as never[])) as T | null) ?? null;
  }

  async all<T>(): Promise<{ results: T[]; success: true }> {
    return { results: this.db.prepare(this.sql).all(...(this.params as never[])) as T[], success: true };
  }

  async run(): Promise<{ success: true; results: []; meta: { changes: number } }> {
    const { changes } = this.db.prepare(this.sql).run(...(this.params as never[]));
    return { success: true, results: [], meta: { changes } };
  }
}

/** Minimal D1 stand-in backed by bun:sqlite, covering the calls this project makes. */
export function d1(db: Database): D1Database {
  return {
    prepare: (sql: string) => new Statement(db, sql),
    batch: async (statements: Statement[]) => {
      const results: unknown[] = [];
      db.transaction(() => {
        for (const statement of statements) results.push(statement.run());
      })();
      return Promise.all(results);
    },
  } as unknown as D1Database;
}

export function migratedDatabase(): Database {
  const db = new Database(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  const dir = join(import.meta.dir, "../../migrations");
  for (const file of readdirSync(dir).filter((name) => name.endsWith(".sql")).sort()) {
    db.exec(readFileSync(join(dir, file), "utf8"));
  }
  return db;
}

export const ORIGIN = "https://auth.test";

export function testEnv(db: Database, overrides: Partial<Env> = {}): Env {
  return {
    DB: d1(db),
    BETTER_AUTH_SECRET: "test-secret-test-secret-test-secret-0123",
    ADMIN_TOKEN: "test-admin-token",
    APP_NAME: "Test App",
    PUBLIC_ORIGIN: ORIGIN,
    TURNSTILE_ENABLED: "false",
    CLOUDFLARE_ACCOUNT_ID: "account",
    ACCESS_POLICY_ID: "policy",
    CLOUDFLARE_API_TOKEN: "token",
    INVITATION_FROM: "auth@send.test",
    INVITE_RATE_LIMITER: { limit: async () => ({ success: true }) },
    ...overrides,
  } as Env;
}

/** Better Auth gets the raw sqlite handle; the app's D1 calls share the same connection. */
export function testAuth(db: Database, env: Env) {
  return createAuth({ ...env, DB: db as unknown as D1Database }, new Request(`${ORIGIN}/`));
}
