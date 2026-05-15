"use client";

import { useEffect, useMemo, useRef, useState, useTransition } from "react";
import { createPortal } from "react-dom";
import { useRouter } from "next/navigation";
import {
  loadAttackTaxonomyAction,
  loadRerunCandidatesAction,
  startCampaignAction,
  startWideSweepAction,
  type StartCampaignActionState,
  type StartWideSweepActionState,
} from "@/app/campaigns/actions";
import type {
  AttackTaxonomy,
  VulnerabilitySummary,
  WideSweepBreadth,
} from "@/types";
import styles from "@/app/dashboard.module.css";

interface StartCampaignModalProps {
  open: boolean;
  onClose: () => void;
}

type Mode = "live" | "smoke";
type Targeting = "new" | "rerun" | "sweep";

// Hardcoded breadth bucket sizes mirror the seeded attack_taxonomy
// distribution (alembic 0003): 4 critical, 9 high, 3 medium, 0 low.
// If the taxonomy ever shifts, the API still returns the true count in
// the WideSweepResult — these constants are display-only.
const SWEEP_BUCKET_COUNTS: Record<WideSweepBreadth, number> = {
  critical: 4,
  critical_plus_high: 13,
  all: 16,
};

export function StartCampaignModal({ open, onClose }: StartCampaignModalProps) {
  const [budget, setBudget] = useState<string>("5");
  const [mode, setMode] = useState<Mode>("live");
  const [targeting, setTargeting] = useState<Targeting>("new");
  const [category, setCategory] = useState<string>("");
  const [subcategory, setSubcategory] = useState<string>("");
  const [vulnId, setVulnId] = useState<string>("");
  const [variantCount, setVariantCount] = useState<string>("20");
  const [sweepBreadth, setSweepBreadth] =
    useState<WideSweepBreadth>("critical");
  const [sweepBudget, setSweepBudget] = useState<string>("1.50");
  const [sweepVariantCount, setSweepVariantCount] = useState<string>("20");
  const [sweepStagger, setSweepStagger] = useState<string>("10");
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
  if (typeof document === "undefined") return null;

  const sweepCount = SWEEP_BUCKET_COUNTS[sweepBreadth];
  const sweepBudgetNum = parseFloat(sweepBudget);
  const sweepTotal = Number.isFinite(sweepBudgetNum)
    ? sweepBudgetNum * sweepCount
    : 0;

  const clientValidate = (): string | null => {
    if (targeting === "sweep") {
      const sb = parseFloat(sweepBudget);
      if (!Number.isFinite(sb) || sb < 0.1 || sb > 50) {
        return "Wide Sweep per-campaign budget must be between 0.10 and 50.00 USD.";
      }
      const sv = parseInt(sweepVariantCount, 10);
      if (!Number.isFinite(sv) || sv < 1 || sv > 50) {
        return "Wide Sweep variant count must be between 1 and 50.";
      }
      const ss = parseInt(sweepStagger, 10);
      if (!Number.isFinite(ss) || ss < 0 || ss > 300) {
        return "Stagger seconds must be between 0 and 300.";
      }
      return null;
    }
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

    if (targeting === "sweep") {
      // Build a fresh FormData for the sweep action — the modal's hidden
      // start-campaign inputs are not part of the /campaigns/sweep contract.
      const sweepForm = new FormData();
      sweepForm.set("breadth", sweepBreadth);
      sweepForm.set("budget_per_campaign_usd", sweepBudget);
      sweepForm.set("variant_count", sweepVariantCount);
      sweepForm.set("stagger_seconds", sweepStagger);
      startTransition(async () => {
        const initial: StartWideSweepActionState = { ok: false };
        const result = await startWideSweepAction(initial, sweepForm);
        if (result.ok) {
          onClose();
          // Land on the dashboard so the operator can watch campaigns
          // light up one by one. No single campaign_id to deep-link to.
          router.push("/");
          router.refresh();
          return;
        }
        setError(result.error ?? "Failed to start Wide Sweep");
      });
      return;
    }

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

  return createPortal(
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
          {targeting !== "sweep" && (
          <>
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
          </>
          )}
          {/* end non-sweep budget+mode block */}

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
              <button
                type="button"
                role="radio"
                aria-checked={targeting === "sweep"}
                className={`${styles.modalToggleBtn} ${
                  targeting === "sweep" ? styles.modalToggleBtnActive : ""
                }`}
                onClick={() => setTargeting("sweep")}
              >
                Wide Sweep
              </button>
            </div>
            <div className={styles.modalHint}>
              {targeting === "new"
                ? "Optionally pin a category/subcategory; otherwise the Orchestrator picks."
                : targeting === "rerun"
                  ? "Replay a known vulnerability's exact attack input through all four mutation strategies."
                  : "Fire N campaigns back-to-back across a breadth slice of the attack surface."}
            </div>
          </div>

          {targeting === "sweep" ? (
            <>
              <div className={styles.modalField}>
                <span className={styles.modalLabel}>Breadth</span>
                <div
                  className={styles.modalToggle}
                  role="radiogroup"
                  aria-label="Breadth"
                >
                  <button
                    type="button"
                    role="radio"
                    aria-checked={sweepBreadth === "critical"}
                    className={`${styles.modalToggleBtn} ${
                      sweepBreadth === "critical"
                        ? styles.modalToggleBtnActive
                        : ""
                    }`}
                    onClick={() => setSweepBreadth("critical")}
                  >
                    CRITICAL only (~{SWEEP_BUCKET_COUNTS.critical} subs)
                  </button>
                  <button
                    type="button"
                    role="radio"
                    aria-checked={sweepBreadth === "critical_plus_high"}
                    className={`${styles.modalToggleBtn} ${
                      sweepBreadth === "critical_plus_high"
                        ? styles.modalToggleBtnActive
                        : ""
                    }`}
                    onClick={() => setSweepBreadth("critical_plus_high")}
                  >
                    CRITICAL + HIGH (~{SWEEP_BUCKET_COUNTS.critical_plus_high}{" "}
                    subs)
                  </button>
                  <button
                    type="button"
                    role="radio"
                    aria-checked={sweepBreadth === "all"}
                    className={`${styles.modalToggleBtn} ${
                      sweepBreadth === "all"
                        ? styles.modalToggleBtnActive
                        : ""
                    }`}
                    onClick={() => setSweepBreadth("all")}
                  >
                    All {SWEEP_BUCKET_COUNTS.all} subs
                  </button>
                </div>
              </div>

              <div className={styles.modalField}>
                <label
                  className={styles.modalLabel}
                  htmlFor="sc-sweep-budget"
                >
                  Budget per campaign (USD)
                </label>
                <input
                  id="sc-sweep-budget"
                  type="number"
                  min={0.1}
                  max={50}
                  step={0.1}
                  required
                  value={sweepBudget}
                  onChange={(e) => setSweepBudget(e.target.value)}
                  className={styles.modalInput}
                />
                <div className={styles.modalHint}>
                  Each campaign is capped at this amount independently.
                </div>
              </div>

              <div className={styles.modalField}>
                <label
                  className={styles.modalLabel}
                  htmlFor="sc-sweep-variants"
                >
                  Variants per campaign
                </label>
                <input
                  id="sc-sweep-variants"
                  type="number"
                  min={1}
                  max={50}
                  step={1}
                  value={sweepVariantCount}
                  onChange={(e) => setSweepVariantCount(e.target.value)}
                  className={styles.modalInput}
                />
              </div>

              <div className={styles.modalField}>
                <label
                  className={styles.modalLabel}
                  htmlFor="sc-sweep-stagger"
                >
                  Stagger (seconds)
                </label>
                <input
                  id="sc-sweep-stagger"
                  type="number"
                  min={0}
                  max={300}
                  step={1}
                  value={sweepStagger}
                  onChange={(e) => setSweepStagger(e.target.value)}
                  className={styles.modalInput}
                />
                <div className={styles.modalHint}>
                  Wall-clock pause between campaigns. Lets you halt mid-sweep
                  and keeps OpenRouter rate limits happy.
                </div>
              </div>

              <div
                className={styles.modalError}
                role="note"
                style={{
                  background: "rgba(255, 215, 0, 0.08)",
                  borderColor: "rgba(255, 215, 0, 0.45)",
                  color: "#d8b800",
                }}
              >
                <strong>WARNING:</strong> This will fire {sweepCount} campaigns
                back-to-back, each making up to {sweepVariantCount} attacks
                against the live target.{" "}
                {sweepCount} × ${sweepBudgetNum.toFixed(2)} ={" "}
                <strong>${sweepTotal.toFixed(2)}</strong> estimated total.
                Make sure your budget supports this. Each campaign runs to
                completion before the next starts (staggered by {sweepStagger}s
                to avoid OpenRouter rate limits). Halt any campaign mid-sweep
                via the dashboard if you need to abort.
              </div>
            </>
          ) : targeting === "new" ? (
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
              {isPending
                ? targeting === "sweep"
                  ? "Launching Sweep…"
                  : "Starting…"
                : targeting === "sweep"
                  ? "Launch Sweep"
                  : "Launch"}
            </button>
          </div>
        </form>
      </div>
    </div>,
    document.body,
  );
}
