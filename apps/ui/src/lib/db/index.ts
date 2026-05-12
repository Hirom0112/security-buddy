// Slice 0: porsager/postgres client factory — stubbed.
// The client is installed as a dependency and will be wired to DATABASE_URL
// in Slice 7 when the dashboard reads live data from Postgres.
//
// TODO(slice-7): instantiate postgres(env.DATABASE_URL) here and export the
// sql tag for use in server components.

export type { Sql } from "postgres";

// Placeholder — returns undefined so server components can detect Slice 0 stub.
export function getDb(): undefined {
  return undefined;
}
