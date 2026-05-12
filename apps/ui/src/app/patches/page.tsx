import { redirect } from "next/navigation";
import Link from "next/link";
import { getSession } from "@/lib/auth/session";
import { ThemedShell } from "@/components/themed-shell";
import { PatchStatusBadge } from "@/components/badges";
import { listPatches } from "@/lib/db/queries";
import { reviewPatchAction } from "./actions";
import styles from "@/app/dashboard.module.css";

export const dynamic = "force-dynamic";

export default async function PatchesPage() {
  const session = await getSession();
  if (session === null) redirect("/login");

  let patches;
  try {
    patches = await listPatches();
  } catch (err) {
    return (
      <ThemedShell eyebrow="// Patches" title="Patches">
        <DbError error={err} />
      </ThemedShell>
    );
  }

  const pending = patches.filter((p) => p.status === "awaiting_human_review");
  const resolved = patches.filter((p) => p.status !== "awaiting_human_review");

  return (
    <ThemedShell
      eyebrow="// Patches"
      title="Patches"
      meta={
        <>
          <span>{patches.length} TOTAL</span>
          <span className={styles.heroSubDivider} />
          <span style={{ color: "var(--sb-warn)" }}>
            {pending.length} PENDING REVIEW
          </span>
          <span className={styles.heroSubDivider} />
          <span>{resolved.length} CLOSED</span>
        </>
      }
    >
      <div className={styles.panelStack}>
        <div className={styles.panel}>
          <div className={styles.panelHeader}>
            <div className={styles.panelHeaderLeft}>
              <div className={`${styles.panelTitle} ${styles.panelTitleAlert}`}>
                Pending Review
                <span className={styles.panelCount}>({pending.length})</span>
              </div>
              <div className={styles.panelSubtitle}>
                Merge happens on GitHub. The buttons below mark the patch row
                in Postgres after you act on the PR. Merging the PR on GitHub
                also flips this row via the webhook.
              </div>
            </div>
          </div>
          <div className={styles.panelBody}>
            {pending.length === 0 ? (
              <div className={styles.panelEmpty}>
                No patches awaiting review.
              </div>
            ) : (
              <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
                {pending.map((p) => (
                  <li key={p.id} className={styles.reviewItem}>
                    <div>
                      <div className={styles.reviewItemHead}>
                        <a
                          href={p.pr_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className={styles.reviewBranch}
                        >
                          {p.branch_name}
                        </a>
                        <PatchStatusBadge status={p.status} />
                      </div>
                      <div className={styles.reviewMeta}>
                        {p.vuln_id !== null && (
                          <Link
                            href={`/vulnerabilities/${p.vulnerability_id}`}
                            className={styles.dataLink}
                            style={{ fontFamily: "DM Mono, monospace" }}
                          >
                            {p.vuln_id}
                          </Link>
                        )}
                        <span>
                          Opened {new Date(p.created_at).toLocaleString()}
                        </span>
                      </div>
                    </div>
                    <div className={styles.reviewActions}>
                      <form action={reviewPatchAction}>
                        <input type="hidden" name="id" value={p.id} />
                        <input type="hidden" name="decision" value="merged" />
                        <button
                          type="submit"
                          className={`${styles.btn} ${styles.btnPrimary}`}
                        >
                          Mark merged
                        </button>
                      </form>
                      <form action={reviewPatchAction}>
                        <input type="hidden" name="id" value={p.id} />
                        <input type="hidden" name="decision" value="rejected" />
                        <button
                          type="submit"
                          className={`${styles.btn} ${styles.btnDanger}`}
                        >
                          Reject
                        </button>
                      </form>
                      <form action={reviewPatchAction}>
                        <input type="hidden" name="id" value={p.id} />
                        <input
                          type="hidden"
                          name="decision"
                          value="ci_failed"
                        />
                        <button type="submit" className={styles.btn}>
                          CI failed
                        </button>
                      </form>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>

        <div className={styles.panel}>
          <div className={styles.panelHeader}>
            <div className={styles.panelHeaderLeft}>
              <div className={styles.panelTitle}>
                Closed
                <span className={styles.panelCount}>({resolved.length})</span>
              </div>
            </div>
          </div>
          <div className={styles.panelBody}>
            {resolved.length === 0 ? (
              <div className={styles.panelEmpty}>No closed patches yet.</div>
            ) : (
              <div style={{ overflowX: "auto" }}>
                <table className={styles.dataTable}>
                  <thead>
                    <tr>
                      <th>Branch</th>
                      <th>Vuln</th>
                      <th>Status</th>
                      <th>Opened</th>
                      <th>Merged</th>
                    </tr>
                  </thead>
                  <tbody>
                    {resolved.map((p) => (
                      <tr key={p.id}>
                        <td>
                          <a
                            href={p.pr_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className={`${styles.dataLink} ${styles.dataMono}`}
                          >
                            {p.branch_name}
                          </a>
                        </td>
                        <td className={`${styles.dataMono} ${styles.dataMuted}`}>
                          {p.vuln_id ?? "—"}
                        </td>
                        <td>
                          <PatchStatusBadge status={p.status} />
                        </td>
                        <td className={`${styles.dataMono} ${styles.dataMuted}`}>
                          {new Date(p.created_at).toLocaleString()}
                        </td>
                        <td className={`${styles.dataMono} ${styles.dataMuted}`}>
                          {p.merged_at
                            ? new Date(p.merged_at).toLocaleString()
                            : "—"}
                        </td>
                      </tr>
                    ))}
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

function DbError({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error);
  return (
    <div className={styles.dbError}>
      <div className={styles.dbErrorTitle}>Database unreachable</div>
      <div className={styles.dbErrorBody}>{message}</div>
    </div>
  );
}
