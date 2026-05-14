"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";
import { ApiError, startCampaign } from "@/lib/api/client";

const startCampaignSchema = z.object({
  budget_usd: z.coerce.number().min(0.5).max(100),
  mode: z.enum(["live", "smoke"]),
  target_subcategory: z.string().trim().max(100).optional(),
});

export interface StartCampaignActionState {
  ok: boolean;
  error?: string | undefined;
  campaign_id?: string | undefined;
}

export async function startCampaignAction(
  _prev: StartCampaignActionState,
  formData: FormData,
): Promise<StartCampaignActionState> {
  const raw = {
    budget_usd: formData.get("budget_usd") ?? "",
    mode: formData.get("mode") ?? "live",
    target_subcategory: formData.get("target_subcategory") ?? undefined,
  };

  const parsed = startCampaignSchema.safeParse(raw);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    const path = first?.path.join(".") ?? "input";
    return { ok: false, error: `${path}: ${first?.message ?? "invalid"}` };
  }

  const { budget_usd, mode, target_subcategory } = parsed.data;

  try {
    const result = await startCampaign({
      budget_usd,
      mode,
      target_subcategory:
        target_subcategory && target_subcategory !== ""
          ? target_subcategory
          : undefined,
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
