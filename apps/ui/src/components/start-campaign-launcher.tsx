"use client";

import { useState } from "react";
import { StartCampaignModal } from "./start-campaign-modal";
import styles from "@/app/dashboard.module.css";

interface Props {
  label?: string;
  disabled?: boolean;
}

export function StartCampaignLauncher({
  label = "Start Campaign",
  disabled = false,
}: Props) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button
        type="button"
        className={styles.startCampaignInline}
        onClick={() => setOpen(true)}
        disabled={disabled}
        aria-disabled={disabled}
        title={
          disabled ? "Halt the active campaign first" : "Start a new campaign"
        }
      >
        {disabled ? "Campaign Active" : label}
      </button>
      <StartCampaignModal open={open} onClose={() => setOpen(false)} />
    </>
  );
}
