"use client";

import { useEffect, useRef, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  startCampaignAction,
  type StartCampaignActionState,
} from "@/app/campaigns/actions";
import styles from "@/app/dashboard.module.css";

interface StartCampaignModalProps {
  open: boolean;
  onClose: () => void;
}

type Mode = "live" | "smoke";

export function StartCampaignModal({ open, onClose }: StartCampaignModalProps) {
  const [budget, setBudget] = useState<string>("5");
  const [mode, setMode] = useState<Mode>("live");
  const [subcategory, setSubcategory] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();
  const router = useRouter();
  const backdropRef = useRef<HTMLDivElement | null>(null);
  const firstFieldRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (!open) return;
    setError(null);
    firstFieldRef.current?.focus();
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  const submit = (formData: FormData): void => {
    setError(null);
    startTransition(async () => {
      const initial: StartCampaignActionState = { ok: false };
      const result = await startCampaignAction(initial, formData);
      if (result.ok && result.campaign_id !== undefined) {
        onClose();
        router.push(`/campaigns/${result.campaign_id}`);
        router.refresh();
        return;
      }
      setError(result.error ?? "Failed to start campaign");
    });
  };

  return (
    <div
      ref={backdropRef}
      className={styles.modalBackdrop}
      onMouseDown={(e) => {
        if (e.target === backdropRef.current) onClose();
      }}
      role="dialog"
      aria-modal="true"
      aria-labelledby="start-campaign-title"
    >
      <div className={styles.modal}>
        <button
          type="button"
          className={styles.modalClose}
          onClick={onClose}
          aria-label="Close"
        >
          ×
        </button>
        <div className={styles.modalEyebrow}>{"// Initiate Run"}</div>
        <div id="start-campaign-title" className={styles.modalTitle}>
          Start Campaign
        </div>

        <form action={submit}>
          <div className={styles.modalField}>
            <label className={styles.modalLabel} htmlFor="sc-budget">
              Budget (USD)
            </label>
            <input
              ref={firstFieldRef}
              id="sc-budget"
              name="budget_usd"
              type="number"
              min={0.5}
              max={100}
              step={0.5}
              required
              value={budget}
              onChange={(e) => setBudget(e.target.value)}
              className={styles.modalInput}
            />
            <div className={styles.modalHint}>
              Worker enforces this cap regardless of agent suggestion.
            </div>
          </div>

          <div className={styles.modalField}>
            <span className={styles.modalLabel}>Mode</span>
            <div className={styles.modalToggle} role="radiogroup" aria-label="Mode">
              <button
                type="button"
                role="radio"
                aria-checked={mode === "live"}
                className={`${styles.modalToggleBtn} ${
                  mode === "live" ? styles.modalToggleBtnActive : ""
                }`}
                onClick={() => setMode("live")}
              >
                Live
              </button>
              <button
                type="button"
                role="radio"
                aria-checked={mode === "smoke"}
                className={`${styles.modalToggleBtn} ${
                  mode === "smoke" ? styles.modalToggleBtnActive : ""
                }`}
                onClick={() => setMode("smoke")}
              >
                Dry Run
              </button>
            </div>
            <input type="hidden" name="mode" value={mode} />
            <div className={styles.modalHint}>
              {mode === "live"
                ? "Counts on the dashboard, real billable run."
                : "Plumbing/CI run, excluded from dashboard stats."}
            </div>
          </div>

          <div className={styles.modalField}>
            <label className={styles.modalLabel} htmlFor="sc-subcat">
              Target Subcategory (optional)
            </label>
            <input
              id="sc-subcat"
              name="target_subcategory"
              type="text"
              maxLength={100}
              value={subcategory}
              onChange={(e) => setSubcategory(e.target.value)}
              placeholder="leave blank for orchestrator pick"
              autoComplete="off"
              spellCheck={false}
              className={styles.modalInput}
            />
            <div className={styles.modalHint}>
              Must match an attack_taxonomy.subcategory if provided.
            </div>
          </div>

          {error !== null && (
            <div className={styles.modalError} role="alert">
              {error}
            </div>
          )}

          <div className={styles.modalActions}>
            <button
              type="button"
              className={styles.modalCancel}
              onClick={onClose}
              disabled={isPending}
            >
              Cancel
            </button>
            <button
              type="submit"
              className={styles.modalSubmit}
              disabled={isPending}
            >
              {isPending ? "Starting…" : "Launch"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
