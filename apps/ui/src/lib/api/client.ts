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
    // Try RFC 7807 problem+json: surface `detail` if present.
    let detail: string | undefined;
    try {
      const parsed: unknown = JSON.parse(text);
      if (
        parsed !== null &&
        typeof parsed === "object" &&
        "detail" in parsed &&
        typeof (parsed as { detail: unknown }).detail === "string"
      ) {
        detail = (parsed as { detail: string }).detail;
      }
    } catch {
      // not JSON; fall through.
    }
    throw new ApiError(
      detail ?? `API ${path} returned ${resp.status}: ${text.slice(0, 200)}`,
      resp.status
    );
  }
  return resp;
}

// ---------------------------------------------------------------------------
// Campaigns
// ---------------------------------------------------------------------------

export type CampaignStartMode = "live" | "smoke";

export interface StartCampaignInput {
  budget_usd: number;
  mode: CampaignStartMode;
  target_subcategory?: string | undefined;
}

export interface StartCampaignResult {
  campaign_id: string;
  status: string;
  enqueued_at: string;
}

function isStartCampaignResult(v: unknown): v is StartCampaignResult {
  return (
    v !== null &&
    typeof v === "object" &&
    "campaign_id" in v &&
    typeof (v as { campaign_id: unknown }).campaign_id === "string" &&
    "status" in v &&
    typeof (v as { status: unknown }).status === "string" &&
    "enqueued_at" in v &&
    typeof (v as { enqueued_at: unknown }).enqueued_at === "string"
  );
}

export async function startCampaign(
  input: StartCampaignInput
): Promise<StartCampaignResult> {
  const body: Record<string, unknown> = {
    budget_usd: input.budget_usd.toFixed(2),
    mode: input.mode,
  };
  if (input.target_subcategory && input.target_subcategory.trim() !== "") {
    body["target_subcategory"] = input.target_subcategory.trim();
  }
  const resp = await apiFetch("/api/v1/campaigns/start", {
    method: "POST",
    jsonBody: body,
  });
  const data: unknown = await resp.json();
  if (!isStartCampaignResult(data)) {
    throw new ApiError("Unexpected response from /api/v1/campaigns/start", 500);
  }
  return data;
}

// ---------------------------------------------------------------------------
// Halt an in-flight campaign.
//
// Backend contract:
//   POST /api/v1/campaigns/{id}/halt
//   200 — Campaign DTO with status='halted'
//   404 — campaign not found (RFC 7807)
//   409 — campaign is not in {pending, in_progress} OR version conflict
// ---------------------------------------------------------------------------

export async function haltCampaign(campaignId: string): Promise<void> {
  await apiFetch(`/api/v1/campaigns/${encodeURIComponent(campaignId)}/halt`, {
    method: "POST",
  });
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
