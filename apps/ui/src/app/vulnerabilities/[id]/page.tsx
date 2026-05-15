import { notFound, redirect } from "next/navigation";
import { getSession } from "@/lib/auth/session";
import { ThemedShell } from "@/components/themed-shell";
import { SeverityBadge, VulnStatusBadge } from "@/components/badges";
import Link from "next/link";
import {
  countRegressionRunsForVulnerability,
  getLatestRegressionRun,
  getVulnerability,
  listPatchesForVulnerability,
} from "@/lib/db/queries";
import styles from "@/app/dashboard.module.css";
import { confirmVulnerability } from "./actions";
import { DismissForm } from "./dismiss-form";
import { RerunButton } from "./rerun-button";

export const dynamic = "force-dynamic";

interface PageProps {
  params: Promise<{ id: string }>;
}

export default async function VulnerabilityDetailPage({ params }: PageProps) {
  const session = await getSession();
  if (session === null) redirect("/login");

  const { id } = await params;
  const vuln = await getVulnerability(id);
  if (vuln === null) notFound();

  const patches = await listPatchesForVulnerability(id);
  const regressionCount = await countRegressionRunsForVulnerability(id);
  const latestRegression = await getLatestRegressionRun(id);

  // Auto-retry banner inputs: detect whether the vuln has a SUPERSEDED
  // attempt #1 + an active attempt #2, or whether the cap is exhausted.
  // The DB query orders by created_at DESC so patches[0] is the newest.
  const supersededAttempt1 = patches.find(
    (p) => p.status === "superseded" && p.attempt_number === 1,
  );
  const attempt2 = patches.find((p) => p.attempt_number === 2);
  const attempt2IsActive =
    attempt2 !== undefined &&
    (attempt2.status === "awaiting_human_review" ||
      attempt2.status === "merged");
  const retryBanner: { tone: "info" | "alarm"; text: string } | null = (() => {
    if (vuln.status === "unstable" || vuln.status === "regressed") {
      if (attempt2 !== undefined && !attempt2IsActive) {
        // Attempt #2 already landed and we're still in an unstable state.
        return {
          tone: "alarm",
          text: "Attempts exhausted — review required.",
        };
      }
    }
    if (supersededAttempt1 !== undefined && attempt2IsActive) {
      const isMerged = attempt2.status === "merged";
      return {
        tone: "info",
        text: isMerged
          ? `Attempt 2 of 2 — landed as ${attempt2.branch_name}.`
          : "Attempt 1 of 2 — unstable. Auto-retry in progress.",
      };
    }
    return null;
  })();

  return (
    <ThemedShell
      eyebrow={`// ${vuln.vuln_id}`}
      title={vuln.title}
      meta={
        <>
          <SeverityBadge severity={vuln.severity} />
          <VulnStatusBadge status={vuln.status} />
          <span className={styles.heroSubDivider} />
          <span>{new Date(vuln.created_at).toLocaleString()}</span>
        </>
      }
    >
      <div className={styles.panelStack}>
        <div className={`${styles.panel} ${styles.panelTight}`}>
          <div className={styles.panelHeader}>
            <div className={styles.panelHeaderLeft}>
              <div className={styles.panelTitle}>Classification</div>
            </div>
          </div>
          <div className={styles.panelBody}>
            <div className={styles.kvGrid}>
              <div className={styles.kvItem}>
                <span className={styles.kvLabel}>OWASP LLM</span>
                <span className={`${styles.kvValue} ${styles.kvValueNeon}`}>
                  {vuln.owasp_llm_id}
                </span>
              </div>
              <div className={styles.kvItem}>
                <span className={styles.kvLabel}>MITRE ATLAS</span>
                <span className={styles.kvValue}>
                  {vuln.mitre_atlas_technique_id}
                </span>
              </div>
              <div className={styles.kvItem}>
                <span className={styles.kvLabel}>HIPAA</span>
                <span className={styles.kvValue}>{vuln.hipaa_safeguard}</span>
              </div>
            </div>
          </div>
        </div>

        <div className={`${styles.panel} ${styles.panelTight}`}>
          <div className={styles.panelHeader}>
            <div className={styles.panelHeaderLeft}>
              <div className={styles.panelTitle}>Live re-run</div>
              <div className={styles.panelSubtitle}>
                Fire the original attack at the current target deployment.
                Result lands in regression_runs and may flip status.
              </div>
            </div>
          </div>
          <div className={styles.panelBody}>
            <RerunButton
              vulnerabilityId={vuln.id}
              status={vuln.status}
              baselineRegressionRunId={latestRegression?.id ?? null}
            />
          </div>
        </div>

        {vuln.status === "draft" && (
          <div className={styles.alertCallout}>
            <div className={styles.alertCalloutHeader}>
              <span
                className={styles.pulseDot}
                style={{ ["--accent" as string]: "var(--sb-warn)" }}
                aria-hidden="true"
              />
              <span className={styles.alertCalloutTitle}>
                Operator decision required
              </span>
            </div>
            <p className={styles.alertCalloutBody}>
              Critical-severity finding. Confirming flips this to{" "}
              <code>open</code> and queues the Patch Agent. Dismissing
              acknowledges the alert and leaves status unchanged.
            </p>
            <div className={styles.alertCalloutActions}>
              <form action={confirmVulnerability}>
                <input type="hidden" name="id" value={vuln.id} />
                <button
                  type="submit"
                  className={`${styles.btn} ${styles.btnPrimary} ${styles.btnLg}`}
                >
                  Confirm finding
                </button>
              </form>
              <DismissForm vulnerabilityId={vuln.id} />
            </div>
          </div>
        )}

        {vuln.notes && vuln.notes.length > 0 && (
          <div className={styles.panel}>
            <div className={styles.panelHeader}>
              <div className={styles.panelHeaderLeft}>
                <div className={styles.panelTitle}>
                  Operator audit trail
                  <span className={styles.panelCount}>
                    ({vuln.notes.length})
                  </span>
                </div>
                <div className={styles.panelSubtitle}>
                  Durable record of operator actions on this finding.
                </div>
              </div>
            </div>
            <div className={styles.panelBody}>
              <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
                {vuln.notes.map((n, i) => (
                  <li
                    key={`${n.at}-${i}`}
                    className={styles.reviewItem}
                  >
                    <div>
                      <div className={styles.reviewItemHead}>
                        <span style={{ textTransform: "uppercase" }}>
                          {n.action}
                        </span>
                        <span className={styles.dataMuted}>
                          {n.actor} &middot;{" "}
                          {new Date(n.at).toLocaleString()}
                        </span>
                      </div>
                      <p className={styles.proseBody}>{n.reason}</p>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}

        <Section title="Clinical impact" body={vuln.clinical_impact} />
        <Section
          title="Reproduction steps"
          body={vuln.reproduction_steps}
          mono
        />
        <Section title="Observed behavior" body={vuln.observed_behavior} />
        <Section title="Expected behavior" body={vuln.expected_behavior} />
        <Section
          title="Recommended remediation"
          body={vuln.recommended_remediation}
        />

        {retryBanner !== null && (
          <div
            className={styles.alertCallout}
            style={
              retryBanner.tone === "alarm"
                ? ({ ["--accent" as string]: "var(--sb-danger)" } as React.CSSProperties)
                : undefined
            }
          >
            <div className={styles.alertCalloutHeader}>
              <span
                className={styles.pulseDot}
                style={{
                  ["--accent" as string]:
                    retryBanner.tone === "alarm"
                      ? "var(--sb-danger)"
                      : "var(--sb-warn)",
                }}
                aria-hidden="true"
              />
              <span
                className={styles.alertCalloutTitle}
                style={
                  retryBanner.tone === "alarm"
                    ? { color: "var(--sb-danger)" }
                    : undefined
                }
              >
                Patch auto-retry
              </span>
            </div>
            <p className={styles.alertCalloutBody}>{retryBanner.text}</p>
          </div>
        )}

        <div className={styles.panel}>
          <div className={styles.panelHeader}>
            <div className={styles.panelHeaderLeft}>
              <div className={styles.panelTitle}>
                Linked patches
                <span className={styles.panelCount}>({patches.length})</span>
              </div>
            </div>
            {regressionCount > 0 && (
              <Link
                href={`/vulnerabilities/${vuln.id}/diff`}
                className={`${styles.btn} ${styles.btnPrimary}`}
              >
                View before / after diff
              </Link>
            )}
          </div>
          <div className={styles.panelBody}>
            {patches.length === 0 ? (
              <div className={styles.panelEmpty}>
                No patches opened yet for this vulnerability.
              </div>
            ) : (
              <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
                {patches.map((p) => (
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
                        <span className={styles.dataMuted}>
                          attempt {p.attempt_number} ·{" "}
                          {p.status.replace(/_/g, " ")}
                        </span>
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </div>
    </ThemedShell>
  );
}

function Section({
  title,
  body,
  mono = false,
}: {
  title: string;
  body: string;
  mono?: boolean;
}) {
  return (
    <div className={styles.panel}>
      <div className={styles.panelHeader}>
        <div className={styles.panelHeaderLeft}>
          <div className={styles.panelTitle}>{title}</div>
        </div>
      </div>
      <div className={styles.panelBody}>
        {mono ? (
          <pre className={styles.codeBlock}>{body}</pre>
        ) : (
          <p className={styles.proseBody}>{body}</p>
        )}
      </div>
    </div>
  );
}
