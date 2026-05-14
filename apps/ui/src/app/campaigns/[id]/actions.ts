"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";
import { ApiError, haltCampaign } from "@/lib/api/client";

const haltSchema = z.object({
  campaign_id: z.string().uuid(),
});

export interface HaltCampaignActionState {
  ok: boolean;
  error?: string | undefined;
}

export async function haltCampaignAction(
  formData: FormData,
): Promise<HaltCampaignActionState> {
  const raw = {
    campaign_id: formData.get("campaign_id") ?? "",
  };

  const parsed = haltSchema.safeParse(raw);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    const path = first?.path.join(".") ?? "input";
    return { ok: false, error: `${path}: ${first?.message ?? "invalid"}` };
  }

  try {
    await haltCampaign(parsed.data.campaign_id);
    revalidatePath("/");
    revalidatePath("/campaigns");
    revalidatePath(`/campaigns/${parsed.data.campaign_id}`);
    return { ok: true };
  } catch (err) {
    const message =
      err instanceof ApiError
        ? err.message
        : err instanceof Error
          ? err.message
          : "Unknown error halting campaign";
    return { ok: false, error: message };
  }
}
