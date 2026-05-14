import { redirect } from "next/navigation";
import Link from "next/link";
import { getSession } from "@/lib/auth/session";
import { ThemedShell } from "@/components/themed-shell";
import { CampaignStatusBadge } from "@/components/badges";
import { StartCampaignLauncher } from "@/components/start-campaign-launcher";
import { getActiveCampaign, listCampaigns } from "@/lib/db/queries";
import { absoluteIso, bucketFor, relativeTime } from "@/lib/time/relative";
import type { Campaign } from "@/types";
import styles from "@/app/dashboard.module.css";

export const dynamic = "force-dynamic";

const ACTIVE = new Set(["pending", "in_progress"]);

export default async function CampaignsPage() {
  const session = await getSession();
  if (session === null) redirect("/login");

  let campaigns;
  let hasActive = false;
  try {
    [campaigns, hasActive] = await Promise.all([
      listCampaigns(),
      getActiveCampaign().then((c) => c !== null),
    ]);
  } catch (err) {
    return (
      <ThemedShell eyebrow="// Campaigns" title="Campaigns">
        <DbError error={err} />
      </ThemedShell>
    );
  }

  const groups: Record<"active" | "today" | "yesterday" | "earlier", typeof campaigns> = {
    active: [],
    today: [],
    yesterday: [],
    earlier: [],
  };
  for (const c of campaigns) {
    if (ACTIVE.has(c.status)) {
      groups.active.push(c);
    } else {
      groups[bucketFor(c.created_at)].push(c);
    }
  }

  const liveCount = campaigns.filter((c) => c.mode === "live").length;
  const smokeCount = campaigns.length - liveCount;

  return (
    <ThemedShell
      eyebrow="// Campaigns"
      title="Campaigns"
      meta={
        <>
          <span>{campaigns.length} total</span>
          <span className={styles.heroSubDivider} />
          <span className={styles.sectionMetaActive}>{liveCount} live</span>
          {smokeCount > 0 ? (
            <>
              <span className={styles.heroSubDivider} />
              <span>{smokeCount} smoke</span>
            </>
          ) : null}
        </>
      }
    >
      <div className={styles.panelStack}>
        <CampaignGroup
          label="Active"
          tone="active"
          rows={groups.active}
          emptyMessage="No campaign running."
          launcher={<StartCampaignLauncher label="+ New Campaign" disabled={hasActive} />}
        />
        {groups.today.length > 0 && (
          <CampaignGroup label="Today" tone="quiet" rows={groups.today} />
        )}
        {groups.yesterday.length > 0 && (
          <CampaignGroup label="Yesterday" tone="quiet" rows={groups.yesterday} collapsedByDefault />
        )}
        {groups.earlier.length > 0 && (
          <CampaignGroup label="Earlier" tone="quiet" rows={groups.earlier} collapsedByDefault />
        )}
      </div>
    </ThemedShell>
  );
}

function CampaignGroup({
  label,
  rows,
  tone,
  emptyMessage,
  launcher,
  collapsedByDefault = false,
}: {
  label: string;
  rows: readonly Campaign[];
  tone: "active" | "quiet";
  emptyMessage?: string;
  launcher?: React.ReactNode;
  collapsedByDefault?: boolean;
}) {
  const showRows = rows.length > 0;
  const headerCount = rows.length;
  return (
    <details
      className={`${styles.campaignGroup} ${tone === "active" ? styles.campaignGroupActive : ""}`}
      open={!collapsedByDefault}
    >
      <summary className={styles.campaignGroupHeader}>
        <span className={styles.campaignGroupCaret} aria-hidden>▾</span>
        <span className={styles.campaignGroupLabel}>{label}</span>
        <span className={styles.campaignGroupCount}>{headerCount}</span>
        {launcher !== undefined && (
          <span className={styles.campaignGroupAction}>{launcher}</span>
        )}
      </summary>
      {showRows ? (
        <ul className={styles.campaignList}>
          {rows.map((c, idx) => {
            const prevSub = idx > 0 ? rows[idx - 1]?.target_subcategory : null;
            const dedupeSubcategory = prevSub === c.target_subcategory;
            return (
              <li key={c.id} className={styles.campaignRow}>
                <span className={styles.campaignRowSub}>
                  {dedupeSubcategory ? (
                    <span className={styles.campaignRowSubDitto} aria-label="same as above">⌒</span>
                  ) : (
                    <span className={styles.campaignRowSubText}>
                      {c.target_subcategory ?? "Orchestrator selecting"}
                    </span>
                  )}
                </span>
                <span className={styles.campaignRowStatus}>
                  <CampaignStatusBadge status={c.status} />
                  {c.mode === "smoke" && (
                    <span className={styles.campaignRowSmoke}>smoke</span>
                  )}
                </span>
                <time
                  className={styles.campaignRowTime}
                  dateTime={absoluteIso(c.created_at)}
                  title={new Date(c.created_at).toLocaleString()}
                >
                  {relativeTime(c.created_at)}
                </time>
                <span className={styles.campaignRowCost}>
                  ${Number(c.spent_usd).toFixed(2)}
                  <span className={styles.campaignRowCostSep}>/</span>
                  <span className={styles.campaignRowCostBudget}>
                    ${Number(c.budget_usd).toFixed(2)}
                  </span>
                </span>
                <Link
                  href={`/campaigns/${c.id}`}
                  className={styles.campaignRowView}
                  aria-label={`View campaign ${c.id}`}
                >
                  View ›
                </Link>
              </li>
            );
          })}
        </ul>
      ) : (
        <div className={styles.campaignGroupEmpty}>
          {emptyMessage ?? "Nothing here."}
        </div>
      )}
    </details>
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
