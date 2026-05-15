// Server-side fetch helpers for mutating the API.
//
// Reads are direct Postgres via @/lib/db. Writes go through the API's
// authenticated /api/v1/* endpoints. These helpers run inside Next.js
// Server Actions, so the request originates from the server (not the
// browser) — we pass the operator session cookie forward when present.

import { env } from "@/lib/env";
import type {
  AttackTaxonomy,
  VulnerabilityListResponse,
  WideSweepBreadth,
  WideSweepResult,
} from "@/types";

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
  target_category?: string | undefined;
  target_subcategory?: string | undefined;
  rerun_vulnerability_id?: string | undefined;
  variant_count?: number | undefined;
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
  if (input.target_category && input.target_category.trim() !== "") {
    body["target_category"] = input.target_category.trim();
  }
  if (input.target_subcategory && input.target_subcategory.trim() !== "") {
    body["target_subcategory"] = input.target_subcategory.trim();
  }
  if (input.rerun_vulnerability_id !== undefined) {
    body["rerun_vulnerability_id"] = input.rerun_vulnerability_id;
  }
  if (input.variant_count !== undefined) {
    body["variant_count"] = input.variant_count;
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
// Wide Sweep — fire N campaigns back-to-back across a breadth slice.
// ---------------------------------------------------------------------------

export interface StartWideSweepInput {
  breadth: WideSweepBreadth;
  budget_per_campaign_usd: number;
  variant_count: number;
  stagger_seconds: number;
}

function isWideSweepResult(v: unknown): v is WideSweepResult {
  if (v === null || typeof v !== "object") return false;
  const o = v as Record<string, unknown>;
  return (
    Array.isArray(o["subcategories"]) &&
    typeof o["subcategory_count"] === "number" &&
    typeof o["estimated_total_usd"] === "string" &&
    typeof o["sweep_job_id"] === "string" &&
    typeof o["enqueued_at"] === "string"
  );
}

export async function startWideSweep(
  input: StartWideSweepInput
): Promise<WideSweepResult> {
  const body: Record<string, unknown> = {
    breadth: input.breadth,
    budget_per_campaign_usd: input.budget_per_campaign_usd.toFixed(2),
    variant_count: input.variant_count,
    stagger_seconds: input.stagger_seconds,
  };
  const resp = await apiFetch("/api/v1/campaigns/sweep", {
    method: "POST",
    jsonBody: body,
  });
  const data: unknown = await resp.json();
  if (!isWideSweepResult(data)) {
    throw new ApiError("Unexpected response from /api/v1/campaigns/sweep", 500);
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

export type VulnerabilityDecisionPayload =
  | { decision: "confirm" }
  | { decision: "dismiss"; reason: string };

export async function decideVulnerability(
  vulnerabilityId: string,
  payload: VulnerabilityDecisionPayload
): Promise<void> {
  await apiFetch(`/api/v1/vulnerabilities/${vulnerabilityId}/decide`, {
    method: "POST",
    jsonBody: payload,
  });
}

// ---------------------------------------------------------------------------
// Re-run the original attack for a vulnerability. Returns the enqueued
// arq job_id so the UI can correlate poll results if needed.
// ---------------------------------------------------------------------------

export interface RerunVulnerabilityResult {
  vulnerability_id: string;
  job_id: string;
  enqueued_at: string;
}

function isRerunResult(v: unknown): v is RerunVulnerabilityResult {
  return (
    v !== null &&
    typeof v === "object" &&
    "vulnerability_id" in v &&
    typeof (v as { vulnerability_id: unknown }).vulnerability_id === "string" &&
    "job_id" in v &&
    typeof (v as { job_id: unknown }).job_id === "string" &&
    "enqueued_at" in v &&
    typeof (v as { enqueued_at: unknown }).enqueued_at === "string"
  );
}

export async function rerunVulnerability(
  vulnerabilityId: string,
  replays = 1
): Promise<RerunVulnerabilityResult> {
  const resp = await apiFetch(
    `/api/v1/vulnerabilities/${vulnerabilityId}/rerun?replays=${replays}`,
    { method: "POST" }
  );
  const data: unknown = await resp.json();
  if (!isRerunResult(data)) {
    throw new ApiError("Unexpected response from /vulnerabilities/rerun", 500);
  }
  return data;
}

// ---------------------------------------------------------------------------
// Start Campaign modal data: attack taxonomy + rerun-candidate vulns.
// Both are server-action callers (Next.js cookie session forwarded).
// ---------------------------------------------------------------------------

function isAttackTaxonomy(v: unknown): v is AttackTaxonomy {
  if (v === null || typeof v !== "object") return false;
  const cats = (v as { categories: unknown }).categories;
  return Array.isArray(cats);
}

export async function fetchAttackTaxonomy(): Promise<AttackTaxonomy> {
  const resp = await apiFetch("/api/v1/attack_taxonomy", { method: "GET" });
  const data: unknown = await resp.json();
  if (!isAttackTaxonomy(data)) {
    throw new ApiError("Unexpected response from /api/v1/attack_taxonomy", 500);
  }
  return data;
}

function isVulnerabilityList(v: unknown): v is VulnerabilityListResponse {
  if (v === null || typeof v !== "object") return false;
  const items = (v as { items: unknown }).items;
  return Array.isArray(items);
}

export async function fetchRerunCandidates(
  statuses = "regressed,unstable",
  limit = 100
): Promise<VulnerabilityListResponse> {
  const url = `/api/v1/vulnerabilities?status=${encodeURIComponent(
    statuses
  )}&limit=${limit}`;
  const resp = await apiFetch(url, { method: "GET" });
  const data: unknown = await resp.json();
  if (!isVulnerabilityList(data)) {
    throw new ApiError("Unexpected response from /api/v1/vulnerabilities", 500);
  }
  return data;
}
