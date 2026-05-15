"use client";

import { useEffect, useRef, useState } from "react";
import styles from "@/app/dashboard.module.css";
import { rerunVulnerabilityAction } from "./actions";

type BannerKind = "pending" | "safe" | "exploit" | "partial" | "error";

interface BannerState {
  kind: BannerKind;
  message: string;
}

/**
 * Operator "Re-run this attack" button.
 *
 * Click → POST /api/v1/vulnerabilities/{id}/rerun via the server action,
 * which enqueues the harness rerun arq job. We then poll the API for the
 * latest regression_runs row tied to this vulnerability (via a small
 * /api/v1/vulnerabilities/{id} GET head-of-list isn't surfaced — instead
 * we trigger router refresh so the server-rendered Latest Regression Run
 * panel updates on its own).
 *
 * The banner shown here is a transient operator notification only; the
 * authoritative state lives in regression_runs and on the page itself.
 */
export function RerunButton({
  vulnerabilityId,
  status,
  baselineRegressionRunId,
}: {
  vulnerabilityId: string;
  status: string;
  baselineRegressionRunId: string | null;
}) {
  const draft = status === "draft";
  const [busy, setBusy] = useState(false);
  const [banner, setBanner] = useState<BannerState | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(
    () => () => {
      if (pollRef.current !== null) clearInterval(pollRef.current);
    },
    []
  );

  async function pollOnce(): Promise<boolean> {
    try {
      const resp = await fetch(
        `/api/ui/regression-runs/latest?vuln=${encodeURIComponent(vulnerabilityId)}`,
        { cache: "no-store" }
      );
      if (!resp.ok) return false;
      const data: unknown = await resp.json();
      if (
        data === null ||
        typeof data !== "object" ||
        !("id" in data) ||
        !("outcome" in data)
      ) {
        return false;
      }
      const row = data as { id: string; outcome: string };
      if (row.id === baselineRegressionRunId) return false;
      const outcome = row.outcome;
      let kind: BannerKind = "partial";
      let message = "Replay finished — review the regression panel.";
      if (outcome === "fix_verified") {
        kind = "safe";
        message = "Replay safe — fix still holds.";
      } else if (outcome === "regressed") {
        kind = "exploit";
        message = "Replay reproduced the exploit. Vulnerability flipped to regressed.";
      } else if (outcome === "unstable") {
        kind = "partial";
        message = "Replay landed unstable — partial / mixed verdicts.";
      } else if (outcome === "target_unavailable") {
        kind = "error";
        message = "Target unavailable; replay aborted.";
      }
      setBanner({ kind, message });
      setBusy(false);
      return true;
    } catch {
      return false;
    }
  }

  async function onClick(): Promise<void> {
    if (draft || busy) return;
    setBanner({ kind: "pending", message: "Replay enqueued. Re-firing against live target…" });
    setBusy(true);
    try {
      await rerunVulnerabilityAction(vulnerabilityId);
    } catch (err) {
      setBanner({
        kind: "error",
        message: err instanceof Error ? err.message : String(err),
      });
      setBusy(false);
      return;
    }
    // Poll every 3s up to 90s.
    let attempts = 0;
    pollRef.current = setInterval(async () => {
      attempts += 1;
      const landed = await pollOnce();
      if (landed || attempts >= 30) {
        if (pollRef.current !== null) {
          clearInterval(pollRef.current);
          pollRef.current = null;
        }
        if (!landed) {
          setBanner({
            kind: "error",
            message: "Replay timed out waiting for the regression row. Refresh the page.",
          });
          setBusy(false);
        }
      }
    }, 3000);
  }

  const bannerStyle = banner
    ? bannerStyleFor(banner.kind)
    : undefined;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
      <button
        type="button"
        onClick={onClick}
        disabled={draft || busy}
        title={draft ? "Confirm the vuln first" : "Re-fire the original attack against the live target"}
        className={`${styles.btn} ${styles.btnDanger}`}
      >
        {busy ? "Replaying…" : "Re-run this attack"}
      </button>
      {banner && (
        <div
          role="status"
          style={bannerStyle}
          aria-live="polite"
        >
          <strong style={{ marginRight: "0.5rem", letterSpacing: "0.05em" }}>
            {bannerLabel(banner.kind)}
          </strong>
          <span>{banner.message}</span>
        </div>
      )}
    </div>
  );
}

function bannerLabel(kind: BannerKind): string {
  switch (kind) {
    case "pending":
      return "// REPLAYING";
    case "safe":
      return "// SAFE";
    case "exploit":
      return "// EXPLOIT";
    case "partial":
      return "// PARTIAL";
    case "error":
      return "// ERROR";
  }
}

function bannerStyleFor(kind: BannerKind): React.CSSProperties {
  const palette: Record<BannerKind, string> = {
    pending: "var(--sb-warn, #f5a524)",
    safe: "var(--sb-success, #16d4a8)",
    exploit: "var(--sb-danger, #ff2e6c)",
    partial: "var(--sb-warn, #f5a524)",
    error: "var(--sb-danger, #ff2e6c)",
  };
  const accent = palette[kind];
  return {
    padding: "0.6rem 0.75rem",
    border: `1px solid ${accent}`,
    borderLeftWidth: "3px",
    background: "rgba(255,255,255,0.02)",
    color: "var(--sb-fg, #e6e6e6)",
    fontFamily: "var(--sb-mono, ui-monospace, monospace)",
    fontSize: "0.85rem",
  };
}
