"use client";

// Live-status polling widget for the dashboard.
//
// Polls GET /api/campaigns/{id}/live-status every POLL_INTERVAL_MS while the
// campaign is in an active status (pending or in_progress). As soon as the
// backend reports a terminal status the timer is cleared — we render the
// final snapshot and stop hitting the network.
//
// Wire constraints (CLAUDE.md):
//   - No new dependencies. Native fetch + useEffect + useState only.
//   - Mutations always go through /api/v1; this is a read, so it hits the
//     same-origin Next proxy at /api/campaigns/{id}/live-status which
//     forwards to FastAPI.
//   - Response shape is hand-mirrored against CampaignLiveStatusResponse in
//     apps/api/src/routes/campaigns.py. A runtime guard rejects unexpected
//     shapes rather than `as any`-casting.

import type { CSSProperties } from "react";
import { useEffect, useRef, useState } from "react";

const POLL_INTERVAL_MS = 3_000;

const TERMINAL_STATUSES = new Set([
  "completed",
  "halted",
  "budget_exhausted",
  "no_candidates",
]);

interface AttackBuckets {
  pending_execution: number;
  awaiting_judgment: number;
  judged: number;
  total: number;
}

interface VerdictBuckets {
  safe: number;
  exploit: number;
  partial: number;
  unclear: number;
  total: number;
}

interface VulnerabilityBuckets {
  total: number;
  // Per-status keys (draft, confirmed, …) are passed through but only
  // `total` is rendered. Index signature keeps the schema honest without
  // forcing the UI to enumerate every status.
  [status: string]: number;
}

interface CampaignLiveStatus {
  campaign_id: string;
  status: string;
  is_terminal: boolean;
  attacks: AttackBuckets;
  verdicts: VerdictBuckets;
  vulnerabilities: VulnerabilityBuckets;
}

function isNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function parseAttacks(value: unknown): AttackBuckets | null {
  if (value === null || typeof value !== "object") return null;
  const v = value as Record<string, unknown>;
  if (
    !isNumber(v["pending_execution"]) ||
    !isNumber(v["awaiting_judgment"]) ||
    !isNumber(v["judged"]) ||
    !isNumber(v["total"])
  ) {
    return null;
  }
  return {
    pending_execution: v["pending_execution"],
    awaiting_judgment: v["awaiting_judgment"],
    judged: v["judged"],
    total: v["total"],
  };
}

function parseVerdicts(value: unknown): VerdictBuckets | null {
  if (value === null || typeof value !== "object") return null;
  const v = value as Record<string, unknown>;
  if (
    !isNumber(v["safe"]) ||
    !isNumber(v["exploit"]) ||
    !isNumber(v["partial"]) ||
    !isNumber(v["unclear"]) ||
    !isNumber(v["total"])
  ) {
    return null;
  }
  return {
    safe: v["safe"],
    exploit: v["exploit"],
    partial: v["partial"],
    unclear: v["unclear"],
    total: v["total"],
  };
}

function parseVulnerabilities(value: unknown): VulnerabilityBuckets | null {
  if (value === null || typeof value !== "object") return null;
  const v = value as Record<string, unknown>;
  if (!isNumber(v["total"])) return null;
  const out: VulnerabilityBuckets = { total: v["total"] };
  for (const [k, n] of Object.entries(v)) {
    if (isNumber(n)) out[k] = n;
  }
  return out;
}

function parseLiveStatus(value: unknown): CampaignLiveStatus | null {
  if (value === null || typeof value !== "object") return null;
  const v = value as Record<string, unknown>;
  if (
    typeof v["campaign_id"] !== "string" ||
    typeof v["status"] !== "string" ||
    typeof v["is_terminal"] !== "boolean"
  ) {
    return null;
  }
  const attacks = parseAttacks(v["attacks"]);
  const verdicts = parseVerdicts(v["verdicts"]);
  const vulnerabilities = parseVulnerabilities(v["vulnerabilities"]);
  if (attacks === null || verdicts === null || vulnerabilities === null) {
    return null;
  }
  return {
    campaign_id: v["campaign_id"],
    status: v["status"],
    is_terminal: v["is_terminal"],
    attacks,
    verdicts,
    vulnerabilities,
  };
}

interface Props {
  campaignId: string | null;
}

export function LiveCampaignStatus({ campaignId }: Props) {
  const [snapshot, setSnapshot] = useState<CampaignLiveStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const stoppedRef = useRef(false);

  useEffect(() => {
    if (campaignId === null) return;
    stoppedRef.current = false;
    const controller = new AbortController();

    async function poll(): Promise<boolean> {
      try {
        const resp = await fetch(
          `/api/campaigns/${encodeURIComponent(campaignId as string)}/live-status`,
          {
            method: "GET",
            credentials: "same-origin",
            cache: "no-store",
            signal: controller.signal,
          }
        );
        if (!resp.ok) {
          setError(`status ${resp.status}`);
          return false;
        }
        const raw: unknown = await resp.json();
        const parsed = parseLiveStatus(raw);
        if (parsed === null) {
          setError("malformed response");
          return false;
        }
        setSnapshot(parsed);
        setError(null);
        return parsed.is_terminal || TERMINAL_STATUSES.has(parsed.status);
      } catch (err) {
        if (
          err instanceof DOMException &&
          err.name === "AbortError"
        ) {
          return true;
        }
        setError(err instanceof Error ? err.message : "fetch failed");
        return false;
      }
    }

    let timerId: ReturnType<typeof setTimeout> | null = null;
    const tick = async (): Promise<void> => {
      if (stoppedRef.current) return;
      const terminal = await poll();
      if (terminal || stoppedRef.current) return;
      timerId = setTimeout(tick, POLL_INTERVAL_MS);
    };
    void tick();

    return () => {
      stoppedRef.current = true;
      controller.abort();
      if (timerId !== null) clearTimeout(timerId);
    };
  }, [campaignId]);

  if (campaignId === null) {
    return <IdleCard />;
  }
  if (snapshot === null) {
    return <ConnectingCard error={error} />;
  }
  return <StatusCard snapshot={snapshot} error={error} />;
}

// ---------------------------------------------------------------------------
// Presentational pieces. Kept inline (no CSS module) to mirror the existing
// CampaignLiveRefresh aesthetic and to avoid editing dashboard.module.css
// for a single new section.
// ---------------------------------------------------------------------------

function IdleCard() {
  return (
    <div style={panelStyle}>
      <div style={panelHeaderStyle}>
        <span style={dotStyle("var(--muted, #6b7280)")} aria-hidden />
        <span style={panelTitleStyle}>Loop idle</span>
      </div>
      <div style={panelBodyMutedStyle}>
        No active campaign. Press <strong>Start campaign</strong> above to fire
        the loop.
      </div>
    </div>
  );
}

function ConnectingCard({ error }: { error: string | null }) {
  return (
    <div style={panelStyle}>
      <div style={panelHeaderStyle}>
        <span style={dotStyle("var(--accent-amber, #ffb347)")} aria-hidden />
        <span style={panelTitleStyle}>Connecting…</span>
      </div>
      <div style={panelBodyMutedStyle}>
        {error === null
          ? "Fetching the first live snapshot."
          : `Reconnecting (${error}).`}
      </div>
    </div>
  );
}

function StatusCard({
  snapshot,
  error,
}: {
  snapshot: CampaignLiveStatus;
  error: string | null;
}) {
  const terminal =
    snapshot.is_terminal || TERMINAL_STATUSES.has(snapshot.status);
  const dotColor = terminal
    ? "var(--muted, #6b7280)"
    : snapshot.status === "in_progress"
      ? "var(--accent-neon, #00ff9c)"
      : "var(--accent-amber, #ffb347)";
  const label = terminal ? "FINAL" : "LIVE";

  return (
    <div style={panelStyle}>
      <div style={panelHeaderStyle}>
        <span
          style={{
            ...dotStyle(dotColor),
            boxShadow: terminal ? "none" : `0 0 6px ${dotColor}`,
          }}
          aria-hidden
        />
        <span style={panelTitleStyle}>Active campaign</span>
        <span style={statusPillStyle(dotColor)}>{snapshot.status}</span>
        <span style={livePillStyle}>{label}</span>
        {error !== null && (
          <span style={errorPillStyle} title={error}>
            stale
          </span>
        )}
      </div>

      <div style={gridStyle}>
        <Bucket
          heading="Attacks"
          total={snapshot.attacks.total}
          items={[
            ["pending", snapshot.attacks.pending_execution],
            ["awaiting", snapshot.attacks.awaiting_judgment],
            ["judged", snapshot.attacks.judged],
          ]}
        />
        <Bucket
          heading="Verdicts"
          total={snapshot.verdicts.total}
          items={[
            ["safe", snapshot.verdicts.safe],
            ["exploit", snapshot.verdicts.exploit],
            ["partial", snapshot.verdicts.partial],
            ["unclear", snapshot.verdicts.unclear],
          ]}
          accents={{
            exploit: "var(--accent-danger, #ff5470)",
            partial: "var(--accent-amber, #ffb347)",
            safe: "var(--accent-neon, #00ff9c)",
          }}
        />
        <Bucket
          heading="Vulnerabilities"
          total={snapshot.vulnerabilities.total}
          items={[["written", snapshot.vulnerabilities.total]]}
          accents={{
            written:
              snapshot.vulnerabilities.total > 0
                ? "var(--accent-danger, #ff5470)"
                : "var(--muted, #6b7280)",
          }}
        />
      </div>
    </div>
  );
}

function Bucket({
  heading,
  total,
  items,
  accents,
}: {
  heading: string;
  total: number;
  items: ReadonlyArray<readonly [string, number]>;
  accents?: Record<string, string>;
}) {
  return (
    <div style={bucketStyle}>
      <div style={bucketHeaderStyle}>
        <span>{heading}</span>
        <span style={bucketTotalStyle}>{total}</span>
      </div>
      <ul style={bucketListStyle}>
        {items.map(([label, value]) => {
          const accent = accents?.[label] ?? "var(--muted, #6b7280)";
          return (
            <li key={label} style={bucketRowStyle}>
              <span style={{ color: accent }}>{label}</span>
              <span style={bucketValueStyle}>{value}</span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Style helpers.
// ---------------------------------------------------------------------------

const panelStyle: CSSProperties = {
  border: "1px solid rgba(255,255,255,0.08)",
  borderRadius: 12,
  background:
    "linear-gradient(135deg, rgba(8,12,24,0.85), rgba(14,18,32,0.7))",
  padding: "1.1rem 1.25rem 1.25rem",
  fontFamily: "var(--font-mono, ui-monospace, monospace)",
  color: "var(--text, #e5e7eb)",
};

const panelHeaderStyle: CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: "0.6rem",
  marginBottom: "0.85rem",
  fontSize: "0.72rem",
  letterSpacing: "0.08em",
  textTransform: "uppercase",
  color: "var(--muted, #9ca3af)",
};

const panelTitleStyle: CSSProperties = {
  color: "var(--text-strong, #f3f4f6)",
  fontWeight: 600,
};

const panelBodyMutedStyle: CSSProperties = {
  fontSize: "0.85rem",
  color: "var(--muted, #9ca3af)",
};

const gridStyle: CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
  gap: "0.85rem",
};

const bucketStyle: CSSProperties = {
  border: "1px solid rgba(255,255,255,0.06)",
  borderRadius: 8,
  padding: "0.7rem 0.85rem",
  background: "rgba(0,0,0,0.25)",
};

const bucketHeaderStyle: CSSProperties = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "baseline",
  fontSize: "0.7rem",
  letterSpacing: "0.08em",
  textTransform: "uppercase",
  color: "var(--muted, #9ca3af)",
  marginBottom: "0.45rem",
};

const bucketTotalStyle: CSSProperties = {
  fontFamily: "var(--font-bebas, ui-monospace, monospace)",
  fontSize: "1.35rem",
  color: "var(--text-strong, #f3f4f6)",
  letterSpacing: "0.04em",
};

const bucketListStyle: CSSProperties = {
  listStyle: "none",
  margin: 0,
  padding: 0,
  display: "grid",
  gap: "0.25rem",
  fontSize: "0.82rem",
};

const bucketRowStyle: CSSProperties = {
  display: "flex",
  justifyContent: "space-between",
};

const bucketValueStyle: CSSProperties = {
  fontVariantNumeric: "tabular-nums",
  color: "var(--text, #e5e7eb)",
};

const livePillStyle: CSSProperties = {
  marginLeft: "auto",
  padding: "0.15rem 0.5rem",
  borderRadius: 999,
  border: "1px solid rgba(255,255,255,0.12)",
  fontSize: "0.65rem",
  letterSpacing: "0.1em",
  color: "var(--text, #e5e7eb)",
};

const errorPillStyle: CSSProperties = {
  padding: "0.15rem 0.5rem",
  borderRadius: 999,
  border: "1px solid var(--accent-danger, #ff5470)",
  fontSize: "0.65rem",
  letterSpacing: "0.1em",
  color: "var(--accent-danger, #ff5470)",
};

function statusPillStyle(color: string): CSSProperties {
  return {
    padding: "0.15rem 0.55rem",
    borderRadius: 999,
    border: `1px solid ${color}`,
    color,
    fontSize: "0.65rem",
    letterSpacing: "0.08em",
    textTransform: "uppercase",
  };
}

function dotStyle(color: string): CSSProperties {
  return {
    width: 8,
    height: 8,
    borderRadius: 999,
    background: color,
    display: "inline-block",
  };
}
