import { NextResponse } from "next/server";
import { env } from "@/lib/env";
import type { HealthStatus } from "@/types";

/**
 * GET /api/health
 * Proxies to the FastAPI backend /healthz.
 * Falls back to a UI-only response when the backend is unavailable (Slice 0).
 *
 * This endpoint is intentionally unauthenticated — it is used by Railway
 * health checks and the dashboard status indicator.
 */
export async function GET(): Promise<NextResponse<HealthStatus>> {
  try {
    const response = await fetch(`${env.API_BASE_URL}/healthz`, {
      next: { revalidate: 10 },
    });

    if (!response.ok) {
      const fallback: HealthStatus = {
        status: "degraded",
        db: "error",
        redis: "error",
        langsmith: "error",
        version: "unknown",
      };
      return NextResponse.json(fallback, { status: 200 });
    }

    const data = (await response.json()) as HealthStatus;
    return NextResponse.json(data);
  } catch {
    // Backend not yet reachable in Slice 0 — return a degraded status
    const fallback: HealthStatus = {
      status: "degraded",
      db: "error",
      redis: "error",
      langsmith: "error",
      version: "unknown",
    };
    return NextResponse.json(fallback, { status: 200 });
  }
}
