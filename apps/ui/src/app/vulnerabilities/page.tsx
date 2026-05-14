import { redirect } from "next/navigation";
import Link from "next/link";
import { getSession } from "@/lib/auth/session";
import { ThemedShell } from "@/components/themed-shell";
import { SeverityBadge, VulnStatusBadge } from "@/components/badges";
import { listVulnerabilities } from "@/lib/db/queries";
import styles from "@/app/dashboard.module.css";

export const dynamic = "force-dynamic";

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
  const draftOnly = statusFilter === "draft";

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
  const rest = draftOnly
    ? []
    : vulns.filter((v) => v.status !== "draft");
  const openCount = vulns.filter(
    (v) => v.status === "open" || v.status === "draft",
  ).length;

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
        </>
      }
    >
      <div className={styles.panelStack}>
        {drafts.length > 0 && (
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

        {!draftOnly && (
          <div className={styles.panel}>
            <div className={styles.panelHeader}>
              <div className={styles.panelHeaderLeft}>
                <div className={styles.panelTitle}>All Vulnerabilities</div>
              </div>
            </div>
            <div className={styles.panelBody}>
              {rest.length === 0 && drafts.length === 0 ? (
                <div className={styles.panelEmpty}>
                  No vulnerabilities recorded yet.
                </div>
              ) : (
                <VulnTable rows={rest} />
              )}
            </div>
          </div>
        )}
      </div>
    </ThemedShell>
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
              <td className={styles.dataTruncate}>{v.title}</td>
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
