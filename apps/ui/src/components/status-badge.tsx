"use client";

import Link from "next/link";
import { useState } from "react";
import { HaltCampaignButton } from "./halt-campaign-button";
import { StartCampaignModal } from "./start-campaign-modal";
import styles from "@/app/dashboard.module.css";

export interface StatusBadgeProps {
  activeCampaign:
    | {
        id: string;
        target_subcategory: string | null;
        status: string;
      }
    | null;
  draftVulnCount: number;
}

/**
 * Context-aware dashboard status badge.
 *
 * Priority:
 *   1. Active campaign (pending|in_progress) -> RED ATTACK MODE
 *   2. Draft vulnerabilities                 -> AMBER AWAITING REVIEW
 *   3. Otherwise                             -> GREEN LOOP IDLE + Start button
 */
export function StatusBadge({
  activeCampaign,
  draftVulnCount,
}: StatusBadgeProps) {
  const [modalOpen, setModalOpen] = useState(false);

  if (activeCampaign !== null) {
    const sub =
      activeCampaign.target_subcategory ?? "ORCHESTRATOR SELECTING";
    return (
      <>
        <Link
          href={`/campaigns/${activeCampaign.id}`}
          className={`${styles.statusBadge} ${styles.statusBadgeRed}`}
          aria-label={`Active campaign ${activeCampaign.id}`}
        >
          <span
            className={`${styles.statusBadgeDot} ${styles.statusBadgeDotRed}`}
          />
          <span>ATTACK MODE: ENGAGED</span>
          <span className={styles.statusBadgeSub}>{sub}</span>
        </Link>
        <HaltCampaignButton campaignId={activeCampaign.id} variant="inline" />
      </>
    );
  }

  if (draftVulnCount > 0) {
    return (
      <Link
        href="/vulnerabilities?status=draft"
        className={`${styles.statusBadge} ${styles.statusBadgeAmber}`}
        aria-label={`${draftVulnCount} vulnerabilities awaiting review`}
      >
        <span
          className={`${styles.statusBadgeDot} ${styles.statusBadgeDotAmber}`}
        />
        <span>
          {draftVulnCount} VULN{draftVulnCount === 1 ? "" : "S"} AWAITING REVIEW
        </span>
      </Link>
    );
  }

  return (
    <>
      <span
        className={`${styles.statusBadge} ${styles.statusBadgeGreen}`}
        role="status"
      >
        <span
          className={`${styles.statusBadgeDot} ${styles.statusBadgeDotGreen}`}
        />
        <span>LOOP IDLE</span>
      </span>
      <button
        type="button"
        className={styles.startCampaignInline}
        onClick={() => setModalOpen(true)}
      >
        Start Campaign
      </button>
      <StartCampaignModal open={modalOpen} onClose={() => setModalOpen(false)} />
    </>
  );
}
