"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";
import {
  ApiError,
  fetchAttackTaxonomy as apiFetchAttackTaxonomy,
  fetchRerunCandidates as apiFetchRerunCandidates,
  startCampaign,
  startWideSweep,
} from "@/lib/api/client";
import type {
  AttackTaxonomy,
  VulnerabilitySummary,
  WideSweepBreadth,
} from "@/types";

// Accepts three mutually-exclusive targeting modes:
//   1. Orchestrator pick — no targeting fields.
//   2. Subcategory/category pin — at least one of target_category /
//      target_subcategory.
//   3. Rerun-vuln — rerun_vulnerability_id (UUID).
//
// Client-side validation enforces "exactly one mode". The API enforces it
// again and returns 422 with RFC 7807 detail; we surface the detail string.
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const startCampaignSchema = z
  .object({
    budget_usd: z.coerce.number().min(0.1).max(200),
    mode: z.enum(["live", "smoke"]),
    target_category: z.string().trim().max(100).optional(),
    target_subcategory: z.string().trim().max(100).optional(),
    rerun_vulnerability_id: z
      .string()
      .trim()
      .regex(UUID_RE, "must be a UUID")
      .optional(),
    variant_count: z.coerce.number().int().min(1).max(200).optional(),
  })
  .refine(
    (v) => {
      const hasRerun =
        v.rerun_vulnerability_id !== undefined &&
        v.rerun_vulnerability_id !== "";
      const hasPin =
        (v.target_category !== undefined && v.target_category !== "") ||
        (v.target_subcategory !== undefined && v.target_subcategory !== "");
      // hasRerun XOR hasPin is fine; both at once is not.
      return !(hasRerun && hasPin);
    },
    {
      message:
        "rerun_vulnerability_id is mutually exclusive with target_category / target_subcategory",
      path: ["rerun_vulnerability_id"],
    }
  );

export interface StartCampaignActionState {
  ok: boolean;
  error?: string | undefined;
  campaign_id?: string | undefined;
}

function pickStr(form: FormData, key: string): string | undefined {
  const v = form.get(key);
  if (typeof v !== "string") return undefined;
  const t = v.trim();
  return t === "" ? undefined : t;
}

export async function startCampaignAction(
  _prev: StartCampaignActionState,
  formData: FormData
): Promise<StartCampaignActionState> {
  const raw = {
    budget_usd: formData.get("budget_usd") ?? "",
    mode: formData.get("mode") ?? "live",
    target_category: pickStr(formData, "target_category"),
    target_subcategory: pickStr(formData, "target_subcategory"),
    rerun_vulnerability_id: pickStr(formData, "rerun_vulnerability_id"),
    variant_count: pickStr(formData, "variant_count"),
  };

  const parsed = startCampaignSchema.safeParse(raw);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    const path = first?.path.join(".") ?? "input";
    return { ok: false, error: `${path}: ${first?.message ?? "invalid"}` };
  }

  const data = parsed.data;

  try {
    const result = await startCampaign({
      budget_usd: data.budget_usd,
      mode: data.mode,
      target_category: data.target_category,
      target_subcategory: data.target_subcategory,
      rerun_vulnerability_id: data.rerun_vulnerability_id,
      variant_count: data.variant_count,
    });
    revalidatePath("/");
    revalidatePath("/campaigns");
    return { ok: true, campaign_id: result.campaign_id };
  } catch (err) {
    const message =
      err instanceof ApiError
        ? err.message
        : err instanceof Error
          ? err.message
          : "Unknown error starting campaign";
    return { ok: false, error: message };
  }
}

// ---------------------------------------------------------------------------
// Modal data fetchers — exposed as server actions so the client modal can
// pull dropdown sources without learning about the API base URL.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Wide Sweep server action — fire N campaigns back-to-back.
// ---------------------------------------------------------------------------

const wideSweepSchema = z.object({
  breadth: z.enum(["critical", "critical_plus_high", "all"]),
  budget_per_campaign_usd: z.coerce.number().min(0.1).max(50),
  variant_count: z.coerce.number().int().min(1).max(50).default(20),
  stagger_seconds: z.coerce.number().int().min(0).max(300).default(10),
});

export interface StartWideSweepActionState {
  ok: boolean;
  error?: string | undefined;
  sweep_job_id?: string | undefined;
  subcategory_count?: number | undefined;
  estimated_total_usd?: string | undefined;
}

export async function startWideSweepAction(
  _prev: StartWideSweepActionState,
  formData: FormData
): Promise<StartWideSweepActionState> {
  const raw = {
    breadth: formData.get("breadth") ?? "",
    budget_per_campaign_usd: formData.get("budget_per_campaign_usd") ?? "",
    variant_count: formData.get("variant_count") ?? "20",
    stagger_seconds: formData.get("stagger_seconds") ?? "10",
  };
  const parsed = wideSweepSchema.safeParse(raw);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    const path = first?.path.join(".") ?? "input";
    return { ok: false, error: `${path}: ${first?.message ?? "invalid"}` };
  }
  const data = parsed.data;
  try {
    const result = await startWideSweep({
      breadth: data.breadth as WideSweepBreadth,
      budget_per_campaign_usd: data.budget_per_campaign_usd,
      variant_count: data.variant_count,
      stagger_seconds: data.stagger_seconds,
    });
    revalidatePath("/");
    revalidatePath("/campaigns");
    return {
      ok: true,
      sweep_job_id: result.sweep_job_id,
      subcategory_count: result.subcategory_count,
      estimated_total_usd: result.estimated_total_usd,
    };
  } catch (err) {
    const message =
      err instanceof ApiError
        ? err.message
        : err instanceof Error
          ? err.message
          : "Unknown error starting Wide Sweep";
    return { ok: false, error: message };
  }
}

export async function loadAttackTaxonomyAction(): Promise<AttackTaxonomy> {
  return await apiFetchAttackTaxonomy();
}

export async function loadRerunCandidatesAction(): Promise<
  VulnerabilitySummary[]
> {
  const resp = await apiFetchRerunCandidates();
  return resp.items;
}
