import { redirect } from "next/navigation";
import Link from "next/link";
import { getSession } from "@/lib/auth/session";
import { ThemedShell } from "@/components/themed-shell";
import { CampaignStatusBadge } from "@/components/badges";
import { listCampaigns } from "@/lib/db/queries";
import styles from "@/app/dashboard.module.css";

export const dynamic = "force-dynamic";

export default async function CampaignsPage() {
  const session = await getSession();
  if (session === null) redirect("/login");

  let campaigns;
  try {
    campaigns = await listCampaigns();
  } catch (err) {
    return (
      <ThemedShell eyebrow="// Campaigns" title="Campaigns">
        <DbError error={err} />
      </ThemedShell>
    );
  }

  const liveCount = campaigns.filter((c) => c.mode === "live").length;
  const smokeCount = campaigns.length - liveCount;

  return (
    <ThemedShell
      eyebrow="// Campaigns"
      title="Campaigns"
      meta={
        <>
          <span>{campaigns.length} TOTAL</span>
          <span className={styles.heroSubDivider} />
          <span className={styles.sectionMetaActive}>{liveCount} LIVE</span>
          {smokeCount > 0 ? (
            <>
              <span className={styles.heroSubDivider} />
              <span>{smokeCount} SMOKE</span>
            </>
          ) : null}
        </>
      }
    >
      <div className={styles.panel}>
        <div className={styles.panelHeader}>
          <div className={styles.panelHeaderLeft}>
            <div className={styles.panelTitle}>All Campaigns</div>
            <div className={styles.panelSubtitle}>
              Start one with{" "}
              <code>POST /api/v1/campaigns/start</code>. Live runs are counted
              on the dashboard; smoke runs are tagged and excluded.
            </div>
          </div>
        </div>
        <div className={styles.panelBody}>
          {campaigns.length === 0 ? (
            <div className={styles.panelEmpty}>
              No campaigns yet. Fire one to populate the dashboard.
            </div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table className={styles.dataTable}>
                <thead>
                  <tr>
                    <th>Subcategory</th>
                    <th>Status</th>
                    <th>Budget</th>
                    <th>Spent</th>
                    <th>Created</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {campaigns.map((c) => (
                    <tr key={c.id}>
                      <td>
                        <span className={styles.dataMono}>
                          {c.target_subcategory ?? "—"}
                        </span>
                        {c.mode === "smoke" ? (
                          <span
                            className="ml-2 inline-flex items-center rounded border border-[#ffb830]/40 bg-[#ffb830]/10 px-1.5 py-0.5 text-[10px] font-mono uppercase tracking-wider text-[#ffb830]"
                            title="Smoke run — excluded from dashboard stats"
                          >
                            smoke
                          </span>
                        ) : null}
                      </td>
                      <td>
                        <CampaignStatusBadge status={c.status} />
                      </td>
                      <td className={styles.dataMono}>
                        ${Number(c.budget_usd).toFixed(2)}
                      </td>
                      <td className={styles.dataMono}>
                        ${Number(c.spent_usd).toFixed(2)}
                      </td>
                      <td className={`${styles.dataMono} ${styles.dataMuted}`}>
                        {new Date(c.created_at).toLocaleString()}
                      </td>
                      <td>
                        <Link
                          href={`/campaigns/${c.id}`}
                          className={styles.dataLink}
                        >
                          View →
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </ThemedShell>
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
