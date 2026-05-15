// Same-origin JSON endpoint that returns the most recent regression_runs
// row for a given vulnerability_id. The "Re-run this attack" button on the
// vulnerability detail page polls this every 3 seconds while waiting for
// the worker to land a new row.
//
// Architectural note: the UI reads regression_runs straight from Postgres
// (CLAUDE.md §"Server components first" — reads are direct, mutations go
// through the API). This route exists only so the client component can
// poll without re-fetching the entire server-rendered page.

import { getSession } from "@/lib/auth/session";
import { getLatestRegressionRun } from "@/lib/db/queries";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function GET(request: Request): Promise<Response> {
  const session = await getSession();
  if (session === null) {
    return new Response("unauthorized", { status: 401 });
  }

  const url = new URL(request.url);
  const vuln = url.searchParams.get("vuln") ?? "";
  if (!UUID_RE.test(vuln)) {
    return new Response("bad request", { status: 400 });
  }

  const row = await getLatestRegressionRun(vuln);
  if (row === null) {
    return new Response("null", {
      status: 200,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    });
  }
  return new Response(JSON.stringify(row), {
    status: 200,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}
