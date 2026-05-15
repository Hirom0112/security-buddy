// Same-origin JSON proxy for the live-status snapshot.
//
// The dashboard's <LiveCampaignStatus> client component polls this route
// every few seconds while a campaign is active. The proxy mirrors the
// pattern used by /api/campaigns/[id]/events: validate the session cookie
// here, then forward to the FastAPI /api/v1/campaigns/{id}/live-status
// endpoint. The browser never talks to the API host directly.

import { env } from "@/lib/env";
import { getSession } from "@/lib/auth/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

interface RouteContext {
  params: Promise<{ id: string }>;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function GET(
  request: Request,
  context: RouteContext
): Promise<Response> {
  const session = await getSession();
  if (session === null) {
    return new Response("unauthorized", { status: 401 });
  }

  const { id } = await context.params;
  if (!UUID_RE.test(id)) {
    return new Response("bad request", { status: 400 });
  }

  const upstreamUrl = `${env.API_BASE_URL}/api/v1/campaigns/${id}/live-status`;

  const upstream = await fetch(upstreamUrl, {
    method: "GET",
    headers: { Accept: "application/json" },
    signal: request.signal,
    cache: "no-store",
  });

  const body = await upstream.text();
  return new Response(body, {
    status: upstream.status,
    headers: {
      "Content-Type":
        upstream.headers.get("content-type") ?? "application/json",
      "Cache-Control": "no-store",
    },
  });
}
