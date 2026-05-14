"use client";

import { useEffect, useRef, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { haltCampaignAction } from "@/app/campaigns/[id]/actions";
import { useToast } from "@/components/toast/toast-provider";
import styles from "@/app/dashboard.module.css";

export interface HaltCampaignButtonProps {
  campaignId: string;
  /** "inline" = badge-adjacent quick-stop; "primary" = detail-page main button. */
  variant?: "inline" | "primary";
}

/**
 * Two-step inline-confirm halt control.
 *
 *   click 1 → button transforms to "Click again to confirm · 3s" (auto-reverts)
 *   click 2 → fires the action; shows "Halting…" with spinner
 *   success → toast + router.refresh()
 *   failure → sticky error toast (operator can copy the detail)
 *
 * No modal. No window.alert. Linear-style destructive-action affordance.
 */
const CONFIRM_WINDOW_MS = 3_000;

export function HaltCampaignButton({
  campaignId,
  variant = "primary",
}: HaltCampaignButtonProps) {
  const [pending, startTransition] = useTransition();
  const [armed, setArmed] = useState(false);
  const [countdown, setCountdown] = useState(0);
  const router = useRouter();
  const toast = useToast();
  const armedRef = useRef(false);
  armedRef.current = armed;

  // Auto-disarm after the confirm window expires.
  useEffect(() => {
    if (!armed) return;
    setCountdown(Math.ceil(CONFIRM_WINDOW_MS / 1000));
    const ticker = setInterval(() => {
      setCountdown((c) => (c > 1 ? c - 1 : 0));
    }, 1_000);
    const expire = setTimeout(() => setArmed(false), CONFIRM_WINDOW_MS);
    return () => {
      clearInterval(ticker);
      clearTimeout(expire);
    };
  }, [armed]);

  function onClick() {
    if (pending) return;
    if (!armed) {
      setArmed(true);
      return;
    }
    setArmed(false);
    startTransition(async () => {
      const fd = new FormData();
      fd.set("campaign_id", campaignId);
      const result = await haltCampaignAction(fd);
      if (!result.ok) {
        toast.error("Could not halt campaign", result.error);
        return;
      }
      toast.success("Campaign halted");
      router.refresh();
    });
  }

  const className =
    variant === "inline" ? styles.haltCampaignInline : styles.haltCampaignButton;

  const stateClass = pending
    ? styles.haltCampaignPending
    : armed
      ? styles.haltCampaignArmed
      : "";

  const label = pending
    ? "Halting…"
    : armed
      ? `Click again to confirm · ${countdown}s`
      : variant === "inline"
        ? "Halt"
        : "Halt campaign";

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={pending}
      className={`${className} ${stateClass}`}
      aria-label={armed ? "Confirm halt campaign" : "Halt campaign"}
      data-armed={armed ? "true" : undefined}
    >
      <span className={styles.haltCampaignIcon} aria-hidden>
        {pending ? "◐" : armed ? "⏵" : "◼"}
      </span>
      <span>{label}</span>
    </button>
  );
}
