// Server-side fetch helpers for mutating the API.
//
// Reads are direct Postgres via @/lib/db. Writes go through the API's
// authenticated /api/v1/* endpoints. These helpers run inside Next.js
// Server Actions, so the request originates from the server (not the
// browser) — we pass the operator session cookie forward when present.

import { env } from "@/lib/env";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function apiFetch(
  path: string,
  init: RequestInit & { jsonBody?: unknown } = {}
): Promise<Response> {
  const { jsonBody, ...rest } = init;
  const headers = new Headers(rest.headers ?? {});
  if (jsonBody !== undefined) {
    headers.set("Content-Type", "application/json");
  }
  const url = `${env.API_BASE_URL}${path}`;
  const body =
    jsonBody !== undefined ? JSON.stringify(jsonBody) : (rest.body ?? null);
  const resp = await fetch(url, {
    ...rest,
    headers,
    body,
    cache: "no-store",
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new ApiError(
      `API ${path} returned ${resp.status}: ${text.slice(0, 200)}`,
      resp.status
    );
  }
  return resp;
}

// ---------------------------------------------------------------------------
// Patches
// ---------------------------------------------------------------------------

export type PatchDecision = "merged" | "rejected" | "ci_failed";

export async function reviewPatch(
  patchId: string,
  decision: PatchDecision
): Promise<void> {
  await apiFetch(`/api/v1/patches/${patchId}/review`, {
    method: "POST",
    jsonBody: { decision },
  });
}

// ---------------------------------------------------------------------------
// Vulnerabilities (critical-severity soft gate)
//
// The API does not yet expose a status-mutation endpoint for vulnerabilities.
// Slice 7 surfaces the *intent* (operator clicks "Confirm" on a draft) and
// queues it as a server action; the API route lands in a follow-up
// commit. For now, the action throws a clear ApiError so the UI shows the
// missing-endpoint message rather than a misleading success.
// ---------------------------------------------------------------------------

export type VulnerabilityDecision = "confirm" | "dismiss";

export async function decideVulnerability(
  vulnerabilityId: string,
  decision: VulnerabilityDecision
): Promise<void> {
  await apiFetch(`/api/v1/vulnerabilities/${vulnerabilityId}/decide`, {
    method: "POST",
    jsonBody: { decision },
  });
}
