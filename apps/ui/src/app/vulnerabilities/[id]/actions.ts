"use server";

import { revalidatePath } from "next/cache";
import {
  decideVulnerability,
  rerunVulnerability,
  type RerunVulnerabilityResult,
} from "@/lib/api/client";

export async function confirmVulnerability(formData: FormData): Promise<void> {
  const id = String(formData.get("id") ?? "");
  if (id === "") throw new Error("missing vulnerability id");
  await decideVulnerability(id, { decision: "confirm" });
  revalidatePath(`/vulnerabilities/${id}`);
  revalidatePath("/vulnerabilities");
}

export async function dismissVulnerability(formData: FormData): Promise<void> {
  const id = String(formData.get("id") ?? "");
  if (id === "") throw new Error("missing vulnerability id");
  const reason = String(formData.get("reason") ?? "").trim();
  if (reason.length < 4) {
    throw new Error(
      "A dismiss reason of at least 4 characters is required so the audit trail is meaningful.",
    );
  }
  await decideVulnerability(id, { decision: "dismiss", reason });
  revalidatePath(`/vulnerabilities/${id}`);
  revalidatePath("/vulnerabilities");
}

/**
 * Re-run the original attack for a vulnerability. The server action wraps
 * POST /api/v1/vulnerabilities/{id}/rerun and revalidates the detail page
 * so the polling client component picks up the new regression_runs row as
 * soon as the worker writes it.
 */
export async function rerunVulnerabilityAction(
  id: string
): Promise<RerunVulnerabilityResult> {
  if (id === "") throw new Error("missing vulnerability id");
  const result = await rerunVulnerability(id, 1);
  revalidatePath(`/vulnerabilities/${id}`);
  return result;
}
