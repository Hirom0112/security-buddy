import { notFound, redirect } from "next/navigation";
import { getSession } from "@/lib/auth/session";
import { ThemedShell } from "@/components/themed-shell";
import { CampaignStatusBadge, VerdictBadge } from "@/components/badges";
import { CampaignLiveRefresh } from "@/components/campaign-live-refresh";
import { HaltCampaignButton } from "@/components/halt-campaign-button";
import {
  getCampaign,
  listAttacksForCampaign,
  listVerdictsForAttacks,
} from "@/lib/db/queries";
import styles from "@/app/dashboard.module.css";

export const dynamic = "force-dynamic";

interface PageProps {
  params: Promise<{ id: string }>;
}

export default async function CampaignDetailPage({ params }: PageProps) {
  const session = await getSession();
  if (session === null) redirect("/login");

  const { id } = await params;
  const campaign = await getCampaign(id);
  if (campaign === null) notFound();

  const attacks = await listAttacksForCampaign(id);
  const verdicts = await listVerdictsForAttacks(attacks.map((a) => a.id));

  const TERMINAL = new Set([
    "completed",
    "halted",
    "budget_exhausted",
    "no_candidates",
  ]);
  const isTerminal = TERMINAL.has(campaign.status);

  return (
    <ThemedShell
      eyebrow={`// Campaign ${id.slice(0, 8)}`}
      title={campaign.target_subcategory ?? "Campaign"}
      meta={
        <>
          <CampaignStatusBadge status={campaign.status} />
          <CampaignLiveRefresh campaignId={id} isTerminal={isTerminal} />
          {(campaign.status === "pending" ||
            campaign.status === "in_progress") && (
            <HaltCampaignButton campaignId={id} variant="primary" />
          )}
          <span className={styles.heroSubDivider} />
          <span>{attacks.length} ATTACKS</span>
          <span className={styles.heroSubDivider} />
          <span>{new Date(campaign.created_at).toLocaleString()}</span>
        </>
      }
    >
      <div className={styles.panelStack}>
        <div className={`${styles.panel} ${styles.panelTight}`}>
          <div className={styles.panelHeader}>
            <div className={styles.panelHeaderLeft}>
              <div className={styles.panelTitle}>Campaign Metadata</div>
            </div>
          </div>
          <div className={styles.panelBody}>
            <div className={styles.kvGrid}>
              <div className={styles.kvItem}>
                <span className={styles.kvLabel}>ID</span>
                <span className={`${styles.kvValue} ${styles.kvValueMono}`}>
                  {id}
                </span>
              </div>
              <div className={styles.kvItem}>
                <span className={styles.kvLabel}>Subcategory</span>
                <span className={`${styles.kvValue} ${styles.kvValueNeon}`}>
                  {campaign.target_subcategory ?? "—"}
                </span>
              </div>
              <div className={styles.kvItem}>
                <span className={styles.kvLabel}>Budget</span>
                <span className={styles.kvValue}>
                  ${Number(campaign.budget_usd).toFixed(2)}
                </span>
              </div>
              <div className={styles.kvItem}>
                <span className={styles.kvLabel}>Spent</span>
                <span className={styles.kvValue}>
                  ${Number(campaign.spent_usd).toFixed(2)}
                </span>
              </div>
              <div className={styles.kvItem}>
                <span className={styles.kvLabel}>Created</span>
                <span className={styles.kvValue}>
                  {new Date(campaign.created_at).toLocaleString()}
                </span>
              </div>
            </div>
          </div>
        </div>

        <div className={styles.panel}>
          <div className={styles.panelHeader}>
            <div className={styles.panelHeaderLeft}>
              <div className={styles.panelTitle}>
                Attacks
                <span className={styles.panelCount}>({attacks.length})</span>
              </div>
            </div>
          </div>
          <div className={styles.panelBody}>
            {attacks.length === 0 ? (
              <div className={styles.attackEmpty}>
                <div className={styles.attackEmptyTitle}>
                  {isTerminal ? "No attacks were fired" : "Generating attacks…"}
                </div>
                <div className={styles.attackEmptyMeta}>
                  {isTerminal
                    ? "The campaign closed before producing any attack rows. Check the worker logs."
                    : "The Red Team worker is preparing the brief. Attacks will appear here as they land."}
                </div>
                {!isTerminal && (
                  <div
                    className={styles.attackEmptyBar}
                    aria-hidden
                  >
                    <span className={styles.attackEmptyBarFill} />
                  </div>
                )}
              </div>
            ) : (
              <div style={{ overflowX: "auto" }}>
                <table className={styles.dataTable}>
                  <thead>
                    <tr>
                      <th>Mutation</th>
                      <th>Status</th>
                      <th>HTTP</th>
                      <th>Verdict</th>
                      <th>Input (truncated)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {attacks.map((a) => {
                      const v = verdicts.get(a.id);
                      return (
                        <tr key={a.id}>
                          <td className={styles.dataMono}>
                            {a.mutation_strategy}
                          </td>
                          <td className={`${styles.dataMono} ${styles.dataMuted}`}>
                            {a.status.replace(/_/g, " ")}
                          </td>
                          <td className={styles.dataMono}>
                            {a.target_response_status ?? "—"}
                          </td>
                          <td>
                            {v ? <VerdictBadge verdict={v.verdict} /> : "—"}
                          </td>
                          <td className={styles.dataMono}>
                            <details className={styles.payloadDetails}>
                              <summary className={styles.payloadSummary}>
                                <span className={styles.payloadPreview}>
                                  {a.attack_input}
                                </span>
                                <span className={styles.payloadLabel}>
                                  Attack input
                                </span>
                              </summary>
                              <pre className={styles.payloadFull}>
                                {a.attack_input}
                              </pre>
                            </details>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>
    </ThemedShell>
  );
}
