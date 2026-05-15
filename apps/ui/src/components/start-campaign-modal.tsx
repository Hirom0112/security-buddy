"use client";

import { useEffect, useMemo, useRef, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  loadAttackTaxonomyAction,
  loadRerunCandidatesAction,
  startCampaignAction,
  type StartCampaignActionState,
} from "@/app/campaigns/actions";
import type { AttackTaxonomy, VulnerabilitySummary } from "@/types";
import styles from "@/app/dashboard.module.css";

interface StartCampaignModalProps {
  open: boolean;
  onClose: () => void;
}

type Mode = "live" | "smoke";
type Targeting = "new" | "rerun";

export function StartCampaignModal({ open, onClose }: StartCampaignModalProps) {
  const [budget, setBudget] = useState<string>("5");
  const [mode, setMode] = useState<Mode>("live");
  const [targeting, setTargeting] = useState<Targeting>("new");
  const [category, setCategory] = useState<string>("");
  const [subcategory, setSubcategory] = useState<string>("");
  const [vulnId, setVulnId] = useState<string>("");
  const [variantCount, setVariantCount] = useState<string>("20");
  const [taxonomy, setTaxonomy] = useState<AttackTaxonomy | null>(null);
  const [vulns, setVulns] = useState<VulnerabilitySummary[] | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();
  const router = useRouter();
  const backdropRef = useRef<HTMLDivElement | null>(null);
  const firstFieldRef = useRef<HTMLInputElement | null>(null);

  // Fetch dropdown sources on first open. Re-fetching on every open is
  // unnecessary — both lists are stable for the operator's session.
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

  useEffect(() => {
    if (!open) return;
    if (taxonomy !== null && vulns !== null) return;
    let cancelled = false;
    setLoading(true);
    (async () => {
      try {
        const [tax, vs] = await Promise.all([
          taxonomy ?? loadAttackTaxonomyAction(),
          vulns ?? loadRerunCandidatesAction(),
        ]);
        if (cancelled) return;
        setTaxonomy(tax);
        setVulns(vs);
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : "Failed to load options");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [open, taxonomy, vulns]);

  const subcategoriesForCategory = useMemo<string[]>(() => {
    if (taxonomy === null || category === "") return [];
    const found = taxonomy.categories.find((c) => c.category === category);
    return found?.subcategories ?? [];
  }, [taxonomy, category]);

  if (!open) return null;

  const clientValidate = (): string | null => {
    const b = parseFloat(budget);
    if (!Number.isFinite(b) || b < 0.1 || b > 200) {
      return "Budget must be between 0.10 and 200.00 USD.";
    }
    if (targeting === "rerun" && vulnId === "") {
      return "Pick a vulnerability to re-attack.";
    }
    return null;
  };

  const submit = (formData: FormData): void => {
    const clientErr = clientValidate();
    if (clientErr !== null) {
      setError(clientErr);
      return;
    }
    setError(null);
    // Strip the inactive mode's fields so the API's mutual-exclusivity
    // check never fires from a leftover hidden input.
    if (targeting === "rerun") {
      formData.delete("target_category");
      formData.delete("target_subcategory");
    } else {
      formData.delete("rerun_vulnerability_id");
      formData.delete("variant_count");
    }
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
              min={0.1}
              max={200}
              step={0.1}
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
          </div>

          <div className={styles.modalField}>
            <span className={styles.modalLabel}>Targeting</span>
            <div
              className={styles.modalToggle}
              role="radiogroup"
              aria-label="Targeting"
            >
              <button
                type="button"
                role="radio"
                aria-checked={targeting === "new"}
                className={`${styles.modalToggleBtn} ${
                  targeting === "new" ? styles.modalToggleBtnActive : ""
                }`}
                onClick={() => setTargeting("new")}
              >
                New campaign
              </button>
              <button
                type="button"
                role="radio"
                aria-checked={targeting === "rerun"}
                className={`${styles.modalToggleBtn} ${
                  targeting === "rerun" ? styles.modalToggleBtnActive : ""
                }`}
                onClick={() => setTargeting("rerun")}
              >
                Re-attack regressed vuln
              </button>
            </div>
            <div className={styles.modalHint}>
              {targeting === "new"
                ? "Optionally pin a category/subcategory; otherwise the Orchestrator picks."
                : "Replay a known vulnerability's exact attack input through all four mutation strategies."}
            </div>
          </div>

          {targeting === "new" ? (
            <>
              <div className={styles.modalField}>
                <label className={styles.modalLabel} htmlFor="sc-category">
                  Category (optional)
                </label>
                <select
                  id="sc-category"
                  name="target_category"
                  value={category}
                  onChange={(e) => {
                    setCategory(e.target.value);
                    setSubcategory("");
                  }}
                  className={styles.modalInput}
                  disabled={loading || taxonomy === null}
                >
                  <option value="">— Orchestrator picks —</option>
                  {(taxonomy?.categories ?? []).map((c) => (
                    <option key={c.category} value={c.category}>
                      {c.category}
                    </option>
                  ))}
                </select>
              </div>

              <div className={styles.modalField}>
                <label className={styles.modalLabel} htmlFor="sc-subcat">
                  Subcategory (optional)
                </label>
                <select
                  id="sc-subcat"
                  name="target_subcategory"
                  value={subcategory}
                  onChange={(e) => setSubcategory(e.target.value)}
                  className={styles.modalInput}
                  disabled={category === "" || loading}
                >
                  <option value="">
                    {category === ""
                      ? "— Pick a category first —"
                      : "— Orchestrator picks within category —"}
                  </option>
                  {subcategoriesForCategory.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
                <div className={styles.modalHint}>
                  Both fields optional. Leaving blank hands the choice to the
                  Orchestrator&apos;s priority function.
                </div>
              </div>
            </>
          ) : (
            <>
              <div className={styles.modalField}>
                <label className={styles.modalLabel} htmlFor="sc-vuln">
                  Vulnerability
                </label>
                <select
                  id="sc-vuln"
                  name="rerun_vulnerability_id"
                  value={vulnId}
                  onChange={(e) => setVulnId(e.target.value)}
                  className={styles.modalInput}
                  required
                  disabled={loading || vulns === null}
                >
                  <option value="">
                    {loading
                      ? "Loading…"
                      : vulns !== null && vulns.length === 0
                        ? "No regressed/unstable vulns available"
                        : "— Pick a vulnerability —"}
                  </option>
                  {(vulns ?? []).map((v) => (
                    <option key={v.id} value={v.id}>
                      {v.vuln_id} — {v.title} [{v.status}]
                    </option>
                  ))}
                </select>
                <div className={styles.modalHint}>
                  Filtered to status = regressed | unstable. The original
                  attack input is mutated across lexical / structural /
                  multi_turn / llm strategies.
                </div>
              </div>

              <div className={styles.modalField}>
                <label className={styles.modalLabel} htmlFor="sc-variant">
                  Variant count
                </label>
                <input
                  id="sc-variant"
                  name="variant_count"
                  type="number"
                  min={1}
                  max={50}
                  step={1}
                  value={variantCount}
                  onChange={(e) => setVariantCount(e.target.value)}
                  className={styles.modalInput}
                />
                <div className={styles.modalHint}>
                  Worker hard-caps at 50 regardless.
                </div>
              </div>
            </>
          )}

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
              disabled={isPending || loading}
            >
              {isPending ? "Starting…" : "Launch"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
