import { describe, expect, test } from "bun:test";
import { getMigrations } from "better-auth/db/migration";
import { Database } from "bun:sqlite";
import { INVITATION_SCHEMA_STATEMENTS } from "./schema";
import { migratedDatabase, testAuth, testEnv } from "./test/helpers";

describe("schema", () => {
  test("committed migrations satisfy the schema Better Auth expects", async () => {
    const db = migratedDatabase();
    const { toBeCreated, toBeAdded } = await getMigrations(testAuth(db, testEnv(db)).options);
    expect(toBeCreated.map((table) => table.table)).toEqual([]);
    expect(toBeAdded.map((table) => table.table)).toEqual([]);
  });

  test("admin migrate creates the same invitation table as migration 0001", () => {
    const columns = (db: Database) => db.query("PRAGMA table_info(invitation)").all();
    const fromMigrations = migratedDatabase();
    const fromAdmin = new Database(":memory:");
    fromAdmin.exec('CREATE TABLE user (id TEXT PRIMARY KEY)');
    for (const statement of INVITATION_SCHEMA_STATEMENTS) fromAdmin.exec(statement);
    expect(columns(fromAdmin)).toEqual(columns(fromMigrations));
  });
});
