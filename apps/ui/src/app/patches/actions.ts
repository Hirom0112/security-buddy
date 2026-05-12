"use server";

import { revalidatePath } from "next/cache";
import { reviewPatch, type PatchDecision } from "@/lib/api/client";

export async function reviewPatchAction(formData: FormData): Promise<void> {
  const id = String(formData.get("id") ?? "");
  const decisionRaw = String(formData.get("decision") ?? "");
  if (id === "") throw new Error("missing patch id");
  if (
    decisionRaw !== "merged" &&
    decisionRaw !== "rejected" &&
    decisionRaw !== "ci_failed"
  ) {
    throw new Error(`invalid decision: ${decisionRaw}`);
  }
  await reviewPatch(id, decisionRaw as PatchDecision);
  revalidatePath("/patches");
}
