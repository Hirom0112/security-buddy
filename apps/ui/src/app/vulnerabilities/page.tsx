import { redirect } from "next/navigation";
import Link from "next/link";
import { getSession } from "@/lib/auth/session";
import { ThemedShell } from "@/components/themed-shell";
import { SeverityBadge, VulnStatusBadge } from "@/components/badges";
import { listVulnerabilities } from "@/lib/db/queries";
import styles from "@/app/dashboard.module.css";

export const dynamic = "force-dynamic";

const ALL_STATUS_FILTERS = [
  "draft",
  "open",
  "proposed_fix",
  "patched",
  "regressed",
  "unstable",
] as const;
type StatusFilter = (typeof ALL_STATUS_FILTERS)[number];

// Synthetic filter: not a status value, but an audit-trail predicate
// (any vulnerability with an operator-dismiss entry in notes).
const DISMISSED_FILTER = "dismissed";
type Filter = StatusFilter | typeof DISMISSED_FILTER;

interface VulnerabilitiesPageProps {
  searchParams?: Promise<{ status?: string | string[] }>;
}

export default async function VulnerabilitiesPage({
  searchParams,
}: VulnerabilitiesPageProps) {
  const session = await getSession();
  if (session === null) redirect("/login");

  const params = (await searchParams) ?? {};
  const rawStatus = params.status;
  const statusFilter =
    typeof rawStatus === "string" ? rawStatus : rawStatus?.[0];
  const activeFilter = parseFilter(statusFilter);

  let vulns;
  try {
    vulns = await listVulnerabilities();
  } catch (err) {
    return (
      <ThemedShell eyebrow="// Findings" title="Vulnerabilities">
        <DbError error={err} />
      </ThemedShell>
    );
  }

  const drafts = vulns.filter((v) => v.status === "draft");
  const openCount = vulns.filter(
    (v) => v.status === "open" || v.status === "draft",
  ).length;
  const dismissedCount = vulns.filter((v) => v.is_dismissed).length;

  // Filtered "rest" panel:
  //   - no filter → everything except drafts (drafts have their own panel)
  //   - status filter → rows matching that status
  //   - dismissed → only rows where an operator dismiss note exists
  let rest: typeof vulns;
  if (activeFilter === null) {
    rest = vulns.filter((v) => v.status !== "draft");
  } else if (activeFilter === DISMISSED_FILTER) {
    rest = vulns.filter((v) => v.is_dismissed);
  } else if (activeFilter === "draft") {
    rest = [];
  } else {
    rest = vulns.filter((v) => v.status === activeFilter);
  }

  return (
    <ThemedShell
      eyebrow="// Findings"
      title="Vulnerabilities"
      meta={
        <>
          <span>{vulns.length} TOTAL</span>
          <span className={styles.heroSubDivider} />
          <span className={styles.sectionMetaActive}>{openCount} OPEN</span>
          {drafts.length > 0 ? (
            <>
              <span className={styles.heroSubDivider} />
              <span style={{ color: "var(--sb-warn)" }}>
                {drafts.length} AWAITING DECISION
              </span>
            </>
          ) : null}
          {dismissedCount > 0 ? (
            <>
              <span className={styles.heroSubDivider} />
              <span className={styles.dataMuted}>
                {dismissedCount} DISMISSED
              </span>
            </>
          ) : null}
        </>
      }
    >
      <div className={styles.panelStack}>
        <FilterPills active={activeFilter} dismissedCount={dismissedCount} />

        {drafts.length > 0 && activeFilter === null && (
          <div className={styles.panel}>
            <div className={styles.panelHeader}>
              <div className={styles.panelHeaderLeft}>
                <div
                  className={`${styles.panelTitle} ${styles.panelTitleAlert}`}
                >
                  Awaiting Your Decision
                  <span className={styles.panelCount}>({drafts.length})</span>
                </div>
                <div className={styles.panelSubtitle}>
                  Critical-severity findings stay in <code>draft</code> until
                  the operator confirms. Confirming opens the Patch Agent
                  workflow.
                </div>
              </div>
            </div>
            <div className={styles.panelBody}>
              <VulnTable rows={drafts} />
            </div>
          </div>
        )}

        <div className={styles.panel}>
          <div className={styles.panelHeader}>
            <div className={styles.panelHeaderLeft}>
              <div className={styles.panelTitle}>
                {panelTitleFor(activeFilter)}
              </div>
            </div>
          </div>
          <div className={styles.panelBody}>
            {rest.length === 0 ? (
              <div className={styles.panelEmpty}>
                {emptyMessageFor(activeFilter)}
              </div>
            ) : (
              <VulnTable rows={rest} />
            )}
          </div>
        </div>
      </div>
    </ThemedShell>
  );
}

function parseFilter(raw: string | undefined): Filter | null {
  if (raw === undefined) return null;
  if (raw === DISMISSED_FILTER) return DISMISSED_FILTER;
  if ((ALL_STATUS_FILTERS as readonly string[]).includes(raw)) {
    return raw as StatusFilter;
  }
  return null;
}

function panelTitleFor(filter: Filter | null): string {
  if (filter === null) return "All Vulnerabilities";
  if (filter === DISMISSED_FILTER) return "Dismissed Findings (audit trail)";
  return `Status: ${filter.replace(/_/g, " ")}`;
}

function emptyMessageFor(filter: Filter | null): string {
  if (filter === DISMISSED_FILTER) {
    return "No dismissed findings yet. Operator-dismissed drafts will appear here with their reason and timestamp.";
  }
  if (filter !== null) {
    return `No findings with status "${filter}".`;
  }
  return "No vulnerabilities recorded yet.";
}

function FilterPills({
  active,
  dismissedCount,
}: {
  active: Filter | null;
  dismissedCount: number;
}) {
  const items: { label: string; href: string; key: Filter | "all" }[] = [
    { label: "All", href: "/vulnerabilities", key: "all" },
    ...ALL_STATUS_FILTERS.map((s) => ({
      label: s.replace(/_/g, " "),
      href: `/vulnerabilities?status=${s}`,
      key: s,
    })),
    {
      label: `Dismissed${dismissedCount > 0 ? ` (${dismissedCount})` : ""}`,
      href: `/vulnerabilities?status=${DISMISSED_FILTER}`,
      key: DISMISSED_FILTER,
    },
  ];
  return (
    <div
      style={{
        display: "flex",
        flexWrap: "wrap",
        gap: "0.5rem",
        marginBottom: "0.5rem",
      }}
    >
      {items.map((it) => {
        const isActive =
          (it.key === "all" && active === null) || it.key === active;
        return (
          <Link
            key={it.key}
            href={it.href}
            className={`${styles.btn} ${
              isActive ? styles.btnPrimary : ""
            }`.trim()}
            style={{ textTransform: "capitalize" }}
          >
            {it.label}
          </Link>
        );
      })}
    </div>
  );
}

function VulnTable({
  rows,
}: {
  rows: Awaited<ReturnType<typeof listVulnerabilities>>;
}) {
  if (rows.length === 0) {
    return <div className={styles.panelEmpty}>No matching findings.</div>;
  }
  return (
    <div style={{ overflowX: "auto" }}>
      <table className={styles.dataTable}>
        <thead>
          <tr>
            <th>ID</th>
            <th>Title</th>
            <th>Severity</th>
            <th>Status</th>
            <th>OWASP</th>
            <th>Reported</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((v) => (
            <tr key={v.id}>
              <td className={styles.dataMono}>
                <Link
                  href={`/vulnerabilities/${v.id}`}
                  className={styles.dataLink}
                >
                  {v.vuln_id}
                </Link>
              </td>
              <td className={styles.dataTruncate}>
                {v.title}
                {v.is_dismissed && (
                  <span
                    className={styles.dataMuted}
                    style={{ marginLeft: "0.5rem", fontSize: "0.85em" }}
                  >
                    (dismissed)
                  </span>
                )}
              </td>
              <td>
                <SeverityBadge severity={v.severity} />
              </td>
              <td>
                <VulnStatusBadge status={v.status} />
              </td>
              <td className={`${styles.dataMono} ${styles.dataMuted}`}>
                {v.owasp_llm_id}
              </td>
              <td className={`${styles.dataMono} ${styles.dataMuted}`}>
                {new Date(v.created_at).toLocaleString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DbError({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error);
  return (
    <div className={styles.dbError}>
      <div className={styles.dbErrorTitle}>Database unreachable</div>
      <div className={styles.dbErrorBody}>{message}</div>
    </div>
  );
}
