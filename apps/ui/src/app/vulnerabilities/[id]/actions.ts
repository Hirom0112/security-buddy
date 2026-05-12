"use server";

import { revalidatePath } from "next/cache";
import { decideVulnerability } from "@/lib/api/client";

export async function confirmVulnerability(formData: FormData): Promise<void> {
  const id = String(formData.get("id") ?? "");
  if (id === "") throw new Error("missing vulnerability id");
  await decideVulnerability(id, "confirm");
  revalidatePath(`/vulnerabilities/${id}`);
  revalidatePath("/vulnerabilities");
}

export async function dismissVulnerability(formData: FormData): Promise<void> {
  const id = String(formData.get("id") ?? "");
  if (id === "") throw new Error("missing vulnerability id");
  await decideVulnerability(id, "dismiss");
  revalidatePath(`/vulnerabilities/${id}`);
  revalidatePath("/vulnerabilities");
}
