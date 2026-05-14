// Same-origin SSE proxy for campaign progress.
//
// The browser opens an EventSource against this route (same origin → no
// CORS, session cookie attached automatically). We forward the GET to the
// FastAPI /api/v1/campaigns/{id}/events endpoint and stream the body back
// through to the browser unmodified. This keeps the API behind the Next
// edge — the operator's browser never talks to the FastAPI host directly.

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

  const upstreamUrl = `${env.API_BASE_URL}/api/v1/campaigns/${id}/events`;

  // Forward the client's abort signal so we close the upstream stream as
  // soon as the browser disconnects (tab close, navigation, etc.).
  const upstream = await fetch(upstreamUrl, {
    method: "GET",
    headers: { Accept: "text/event-stream" },
    signal: request.signal,
    cache: "no-store",
  });

  if (!upstream.ok || upstream.body === null) {
    return new Response(`upstream ${upstream.status}`, {
      status: upstream.status === 0 ? 502 : upstream.status,
    });
  }

  return new Response(upstream.body, {
    status: 200,
    headers: {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}
