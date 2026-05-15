// Cost dashboard — top-line totals, per-agent rollup, per-campaign rollup.
// Server component; reads agent_traces and campaigns directly via lib/db.
// Slice 7 deferred deliverable (see docs/PLAN.md).

import Link from "next/link";
import { redirect } from "next/navigation";
import { getSession } from "@/lib/auth/session";
import { ThemedShell } from "@/components/themed-shell";
import {
  costPerAgent,
  costPerCampaign,
  costTotals,
} from "@/lib/db/queries";
import styles from "@/app/dashboard.module.css";
import type {
  CostPerAgentRow,
  CostPerCampaignRow,
  CostTotals,
} from "@/types";

export const dynamic = "force-dynamic";

export default async function CostDashboardPage() {
  const session = await getSession();
  if (session === null) redirect("/login");

  let totals: CostTotals;
  let perAgent: CostPerAgentRow[];
  let perCampaign: CostPerCampaignRow[];
  try {
    [totals, perAgent, perCampaign] = await Promise.all([
      costTotals(),
      costPerAgent(),
      costPerCampaign(20),
    ]);
  } catch (err) {
    return (
      <ThemedShell eyebrow="// COST" title="Cost dashboard">
        <DbErrorBanner error={err} />
      </ThemedShell>
    );
  }

  return (
    <ThemedShell
      eyebrow="// COST · SPEND TELEMETRY"
      title="Cost dashboard"
      meta={
        <>
          <span>Total spend {formatUsd2(totals.total_usd)}</span>
          <span>·</span>
          <span>{formatUsd2(totals.spent_24h_usd)} in last 24h</span>
        </>
      }
    >
      <div className={styles.costStack}>
        <TotalsStrip totals={totals} />
        <PerAgentPanel rows={perAgent} />
        <PerCampaignPanel rows={perCampaign} />
      </div>
    </ThemedShell>
  );
}

function TotalsStrip({ totals }: { totals: CostTotals }) {
  return (
    <div className={styles.costMetricGrid}>
      <MetricCard label="Total spend" value={formatUsd4(totals.total_usd)} />
      <MetricCard
        label="Spend last 24h"
        value={formatUsd4(totals.spent_24h_usd)}
      />
      <MetricCard
        label="Calls last 24h"
        value={totals.calls_24h.toLocaleString()}
        plain
      />
      <MetricCard
        label="Avg cost / call (24h)"
        value={formatUsd4(totals.avg_cost_24h_usd)}
      />
    </div>
  );
}

function MetricCard({
  label,
  value,
  plain = false,
}: {
  label: string;
  value: string;
  plain?: boolean;
}) {
  return (
    <div className={styles.costMetricCard}>
      <div className={styles.costMetricLabel}>{label}</div>
      <div
        className={`${styles.costMetricValue} ${plain ? styles.costMetricValuePlain : ""}`}
      >
        {value}
      </div>
    </div>
  );
}

function PerAgentPanel({ rows }: { rows: CostPerAgentRow[] }) {
  return (
    <div className={styles.panel}>
      <div className={styles.panelHeader}>
        <div className={styles.panelHeaderLeft}>
          <div className={styles.panelTitle}>Per-agent spend</div>
          <div className={styles.panelSubtitle}>
            All-time rollup. Latency percentiles computed across every
            recorded LLM call for that agent.
          </div>
        </div>
      </div>
      <div className={styles.panelBody}>
        <table className={styles.dataTable}>
          <thead>
            <tr>
              <th>Agent</th>
              <th className={styles.numCell}>Calls</th>
              <th className={styles.numCell}>Total cost</th>
              <th className={styles.numCell}>Avg cost / call</th>
              <th className={styles.numCell}>p50 latency (ms)</th>
              <th className={styles.numCell}>p95 latency (ms)</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const zero = row.calls === 0;
              return (
                <tr key={row.agent}>
                  <td>
                    <span className={styles.dataMono}>{row.agent}</span>
                  </td>
                  <td
                    className={`${styles.numCell} ${zero ? styles.costZero : ""}`}
                  >
                    {row.calls}
                  </td>
                  <td
                    className={`${styles.numCell} ${zero ? styles.costZero : ""}`}
                  >
                    {zero ? "—" : formatUsd4(row.total_usd)}
                  </td>
                  <td
                    className={`${styles.numCell} ${zero ? styles.costZero : ""}`}
                  >
                    {zero ? "—" : formatUsd4(row.avg_usd)}
                  </td>
                  <td
                    className={`${styles.numCell} ${zero ? styles.costZero : ""}`}
                  >
                    {zero ? "—" : row.p50_ms.toLocaleString()}
                  </td>
                  <td
                    className={`${styles.numCell} ${zero ? styles.costZero : ""}`}
                  >
                    {zero ? "—" : row.p95_ms.toLocaleString()}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function PerCampaignPanel({ rows }: { rows: CostPerCampaignRow[] }) {
  return (
    <div className={styles.panel}>
      <div className={styles.panelHeader}>
        <div className={styles.panelHeaderLeft}>
          <div className={styles.panelTitle}>Per-campaign spend</div>
          <div className={styles.panelSubtitle}>
            20 most recent campaigns by start time. Campaigns with zero
            LLM calls still appear (e.g. ones that halted before any agent
            fired).
          </div>
        </div>
      </div>
      <div className={styles.panelBody}>
        {rows.length === 0 ? (
          <div className={styles.panelEmpty}>No campaigns recorded yet.</div>
        ) : (
          <table className={styles.dataTable}>
            <thead>
              <tr>
                <th>Campaign</th>
                <th>Subcategory</th>
                <th>Status</th>
                <th className={styles.numCell}>Total cost</th>
                <th className={styles.numCell}>Calls</th>
                <th>Started</th>
                <th>Completed</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const zero = row.calls === 0;
                return (
                  <tr key={row.campaign_id}>
                    <td>
                      <Link
                        href={`/campaigns/${row.campaign_id}`}
                        className={`${styles.dataLink} ${styles.dataMono}`}
                      >
                        {row.campaign_id.slice(0, 8)}
                      </Link>
                    </td>
                    <td className={styles.dataMono}>
                      {row.target_subcategory ?? (
                        <span className={styles.dataMuted}>—</span>
                      )}
                    </td>
                    <td className={styles.dataMono}>
                      {row.status.replace(/_/g, " ")}
                    </td>
                    <td
                      className={`${styles.numCell} ${zero ? styles.costZero : ""}`}
                    >
                      {zero ? "—" : formatUsd4(row.total_usd)}
                    </td>
                    <td
                      className={`${styles.numCell} ${zero ? styles.costZero : ""}`}
                    >
                      {row.calls}
                    </td>
                    <td className={styles.dataMuted}>
                      {formatTs(row.started_at)}
                    </td>
                    <td className={styles.dataMuted}>
                      {row.completed_at ? formatTs(row.completed_at) : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// $1.2345 — collapses literal-zero to em-dash to reduce visual noise. The
// /cost dashboard cares about sub-cent precision so we surface 4 decimals.
function formatUsd4(raw: string): string {
  const n = Number(raw);
  if (!Number.isFinite(n) || n === 0) return "—";
  return `$${n.toFixed(4)}`;
}

// $1.23 — two-decimal variant used in the page hero meta line.
function formatUsd2(raw: string): string {
  const n = Number(raw);
  if (!Number.isFinite(n)) return "$0.00";
  return n.toLocaleString("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 2,
  });
}

function formatTs(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function DbErrorBanner({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error);
  return (
    <div className={styles.dbError}>
      <div className={styles.dbErrorTitle}>Database unreachable</div>
      <div className={styles.dbErrorBody}>{message}</div>
    </div>
  );
}
