// porsager/postgres client for server components.
//
// Slice 7 wiring: reads from DATABASE_URL (same Postgres the API uses).
// Server components import { sql } and run typed queries directly — no
// API round-trip for reads. Mutations still go through the FastAPI
// /api/v1/* routes.
//
// The client is constructed lazily on first call so that:
//   - test environments without DATABASE_URL set don't crash on import,
//   - `next build` doesn't try to dial the DB at build time.
//
// SQLAlchemy uses postgresql+asyncpg:// — the postgres driver wants
// plain postgresql://. Strip the suffix here so one DATABASE_URL works
// for both API and UI.

import postgres, { type Sql } from "postgres";

export type { Sql };

let _sql: Sql | undefined;

function dsn(): string {
  const raw = process.env["DATABASE_URL"];
  if (raw === undefined || raw === "") {
    throw new Error(
      "DATABASE_URL is not set — server components cannot read the database."
    );
  }
  return raw.replace(/^postgresql\+asyncpg:\/\//, "postgresql://");
}

export function getSql(): Sql {
  if (_sql === undefined) {
    _sql = postgres(dsn(), {
      max: 5,
      idle_timeout: 30,
      prepare: false,
    });
  }
  return _sql;
}
