import { redirect } from "next/navigation";
import Link from "next/link";
import { Suspense } from "react";
import { Bebas_Neue, DM_Mono, Inter, Nunito } from "next/font/google";
import { getSession } from "@/lib/auth/session";
import { ThemedNav } from "@/components/themed-nav";
import { DashboardHero } from "@/components/dashboard-hero";
import { CountUp } from "@/components/count-up";
import { LiveCampaignStatus } from "@/components/live-campaign-status";
import {
  coverageSnapshot,
  dashboardSummary,
  getActiveCampaign,
} from "@/lib/db/queries";
import type { CoverageRow, DashboardSummary } from "@/types";
import styles from "./dashboard.module.css";

export const dynamic = "force-dynamic";

const inter = Inter({
  weight: ["400", "500", "600", "700"],
  subsets: ["latin"],
  variable: "--font-sans",
  display: "swap",
});
const bebasNeue = Bebas_Neue({
  weight: "400",
  subsets: ["latin"],
  variable: "--font-bebas",
  display: "swap",
});
const dmMono = DM_Mono({
  weight: ["400", "500"],
  subsets: ["latin"],
  variable: "--font-mono",
  display: "swap",
});
const nunito = Nunito({
  weight: ["700", "800", "900"],
  subsets: ["latin"],
  variable: "--font-nunito",
  display: "swap",
});

const PARTICLES = [
  { left: "8%", top: "60%", size: 2, color: "#00f5c4", dur: 6, delay: 0 },
  { left: "20%", top: "70%", size: 1.5, color: "#7c3aed", dur: 8, delay: 1.5 },
  { left: "75%", top: "65%", size: 2, color: "#00f5c4", dur: 7, delay: 0.8 },
  { left: "88%", top: "55%", size: 1, color: "#ffb830", dur: 5, delay: 2 },
  { left: "50%", top: "75%", size: 1.5, color: "#ff3d6b", dur: 9, delay: 3 },
];

export default async function DashboardPage() {
  const session = await getSession();
  if (session === null) redirect("/login");

  let hasActive = false;
  let activeCampaignId: string | null = null;
  try {
    const active = await getActiveCampaign();
    activeCampaignId = active?.id ?? null;
    hasActive = active !== null;
  } catch {
    hasActive = false;
    activeCampaignId = null;
  }

  return (
    <main
      className={`${styles.root} ${inter.variable} ${bebasNeue.variable} ${dmMono.variable} ${nunito.variable}`}
    >
      <div className={styles.gridBg} aria-hidden="true" />
      <div className={styles.scanlines} aria-hidden="true" />
      {PARTICLES.map((p, i) => (
        <span
          key={i}
          className={styles.particle}
          aria-hidden="true"
          style={{
            left: p.left,
            top: p.top,
            width: `${p.size}px`,
            height: `${p.size}px`,
            background: p.color,
            animationDuration: `${p.dur}s`,
            animationDelay: `${p.delay}s`,
          }}
        />
      ))}

      <ThemedNav hasActiveCampaign={hasActive} />
      <DashboardHero />

      <Suspense fallback={<DashboardSkeleton />}>
        <div style={{ padding: "0 2rem", maxWidth: 1400, margin: "0 auto" }}>
          <LiveCampaignStatus campaignId={activeCampaignId} />
        </div>
        <DashboardContent />
      </Suspense>
    </main>
  );
}

async function DashboardContent() {
  let summary: DashboardSummary;
  let coverage: CoverageRow[];
  try {
    [summary, coverage] = await Promise.all([
      dashboardSummary(),
      coverageSnapshot(),
    ]);
  } catch (err) {
    return <DbErrorBanner error={err} />;
  }

  const coveragePct =
    summary.total_subcategories === 0
      ? 0
      : Math.round(
          (summary.covered_subcategories / summary.total_subcategories) * 100,
        );

  const openVulns = Object.values(
    summary.open_vulnerabilities_by_severity,
  ).reduce((a, b) => a + b, 0);

  const attemptedCount = coverage.filter((r) => r.attempts > 0).length;

  return (
    <div className={styles.main}>
      <div className={styles.statGrid}>
        {/* Coverage */}
        <div className={`${styles.statCard} ${styles.statCardCoverage}`}>
          <div className={styles.statLabel}>
            <svg className={styles.statIcon} viewBox="0 0 16 16" fill="none">
              <circle
                cx="8"
                cy="8"
                r="7"
                stroke="currentColor"
                strokeWidth="1.5"
              />
              <path
                d="M8 4v4l3 2"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
              />
            </svg>
            Coverage
          </div>
          <div className={styles.statValue}>
            <CountUp value={summary.covered_subcategories} />
            <span className={styles.statDenom}>
              / {summary.total_subcategories}
            </span>
          </div>
          <div className={styles.coverageBar}>
            <div
              className={styles.coverageFill}
              style={{ ["--fill" as string]: `${coveragePct}%` }}
            />
          </div>
          <div className={styles.statSub}>
            <span className={styles.pulseDot} />
            {coveragePct}% subcategories touched
          </div>
        </div>

        {/* Open Vulnerabilities — primary treatment when there's something to act on */}
        <div
          className={`${styles.statCard} ${styles.statCardVulns} ${
            openVulns > 0 ? styles.statCardPrimary : styles.statCardMuted
          }`}
        >
          <div className={styles.statLabel}>
            <svg className={styles.statIcon} viewBox="0 0 16 16" fill="none">
              <path
                d="M8 2L2 5v5c0 3.3 2.5 6.4 6 7 3.5-.6 6-3.7 6-7V5Z"
                stroke="currentColor"
                strokeWidth="1.5"
              />
              <path
                d="M8 7v3M8 12h.01"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
              />
            </svg>
            Open Vulnerabilities
          </div>
          <div className={`${styles.statValue} ${styles.statValueDanger}`}>
            <CountUp value={openVulns} />
          </div>
          <div className={`${styles.statSub} ${styles.statSubDanger}`}>
            <span
              className={styles.pulseDot}
              style={{ ["--accent" as string]: "var(--sb-danger)" }}
            />
            {openVulns === 0
              ? "No active exploits detected"
              : `${openVulns} active across severities`}
          </div>
        </div>

        {/* Pending PRs */}
        <div className={`${styles.statCard} ${styles.statCardPrs}`}>
          <div className={styles.statLabel}>
            <svg className={styles.statIcon} viewBox="0 0 16 16" fill="none">
              <circle cx="4" cy="4" r="2" stroke="currentColor" strokeWidth="1.5" />
              <circle cx="4" cy="12" r="2" stroke="currentColor" strokeWidth="1.5" />
              <circle cx="12" cy="4" r="2" stroke="currentColor" strokeWidth="1.5" />
              <path
                d="M4 6v4M6 4h4"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
              />
            </svg>
            Pending PRs
          </div>
          <div className={`${styles.statValue} ${styles.statValueWarn}`}>
            <CountUp value={summary.pending_patches} />
          </div>
          <div className={`${styles.statSub} ${styles.statSubWarn}`}>
            <Link href="/patches">View queue →</Link>
          </div>
        </div>

        {/* Cost */}
        <div className={`${styles.statCard} ${styles.statCardCost}`}>
          <div className={styles.statLabel}>
            <svg className={styles.statIcon} viewBox="0 0 16 16" fill="none">
              <circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="1.5" />
              <path
                d="M8 4v1m0 6v1M6 6.5a2 2 0 012-1.5h.5A1.5 1.5 0 0110 6.5v0A1.5 1.5 0 018.5 8h-1A1.5 1.5 0 006 9.5v0A1.5 1.5 0 007.5 11H8a2 2 0 002-1.5"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
              />
            </svg>
            Cost
          </div>
          <div className={`${styles.statValue} ${styles.statValueCost}`}>
            {formatUsd(summary.total_cost_usd)}
          </div>
          <div className={`${styles.statSub} ${styles.statSubCost}`}>
            <span
              className={styles.pulseDot}
              style={{ ["--accent" as string]: "var(--sb-purple)" }}
            />
            {formatUsd(summary.last_24h_cost_usd)} in last 24h
          </div>
        </div>
      </div>

      <div className={styles.sectionHeader}>
        <div className={styles.sectionTitle}>Coverage Map</div>
        <div className={styles.sectionMeta}>
          {summary.total_subcategories} SUBCATEGORIES &nbsp;·&nbsp;
          <span className={styles.sectionMetaActive}>
            {attemptedCount} ATTEMPTED
          </span>
        </div>
      </div>

      <div className={styles.tableWrap}>
        {coverage.length === 0 ? (
          <div className={styles.emptyState}>No attacks fired yet.</div>
        ) : (
          <table className={styles.coverageTable}>
            <thead>
              <tr>
                <th>Category / Subcategory</th>
                <th className={styles.thRight}>Attempts</th>
                <th className={styles.thRight}>Exploits</th>
                <th className={styles.thRight}>Partials</th>
                <th className={styles.thRight}>Last Attempted</th>
              </tr>
            </thead>
            <tbody>
              {coverage.map((row) => {
                const active = row.attempts > 0;
                return (
                  <tr
                    key={`${row.category}/${row.subcategory}`}
                    className={active ? styles.activeRow : undefined}
                  >
                    <td>
                      <span
                        className={`${styles.catLabel} ${categoryClass(row.category, styles)}`}
                      >
                        {row.category}
                      </span>
                      <span className={styles.subLabel}>
                        / {row.category}/{row.subcategory}
                      </span>
                    </td>
                    <td
                      className={`${styles.tdRight} ${active ? styles.attemptsVal : styles.zero}`}
                    >
                      {row.attempts}
                    </td>
                    <td
                      className={`${styles.tdRight} ${row.exploits > 0 ? styles.exploitsVal : styles.zero}`}
                    >
                      {row.exploits}
                    </td>
                    <td
                      className={`${styles.tdRight} ${row.partials > 0 ? styles.partialsVal : styles.zero}`}
                    >
                      {row.partials}
                    </td>
                    <td
                      className={`${styles.tdRight} ${row.last_attempted_at ? styles.dateVal : styles.zero}`}
                    >
                      {row.last_attempted_at
                        ? new Date(row.last_attempted_at).toLocaleString()
                        : "—"}
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

function categoryClass(
  category: string,
  s: Record<string, string>,
): string {
  switch (category) {
    case "data_exfiltration":
      return s.catDataExfiltration ?? "";
    case "dos":
      return s.catDos ?? "";
    case "identity_role":
      return s.catIdentityRole ?? "";
    case "prompt_injection":
      return s.catPromptInjection ?? "";
    default:
      return "";
  }
}

function DashboardSkeleton() {
  return (
    <div className={styles.main}>
      <div className={styles.statGrid}>
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className={styles.statCard}>
            <div className={styles.statLabel}>Loading…</div>
            <div className={styles.statValue}>—</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function DbErrorBanner({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error);
  return (
    <div className={styles.errorBanner}>
      <strong>Database unreachable</strong>
      <div>{message}</div>
      <div style={{ marginTop: 8 }}>
        Set <code>DATABASE_URL</code> and ensure Postgres is reachable from the
        UI process.
      </div>
    </div>
  );
}

function formatUsd(raw: string): string {
  const n = Number(raw);
  if (!Number.isFinite(n)) return "$0.00";
  return n.toLocaleString("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 2,
  });
}
