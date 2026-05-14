import { notFound, redirect } from "next/navigation";
import { getSession } from "@/lib/auth/session";
import { ThemedShell } from "@/components/themed-shell";
import { SeverityBadge, VulnStatusBadge } from "@/components/badges";
import {
  getVulnerability,
  listPatchesForVulnerability,
} from "@/lib/db/queries";
import styles from "@/app/dashboard.module.css";
import {
  confirmVulnerability,
  dismissVulnerability,
} from "./actions";

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
              <form action={dismissVulnerability}>
                <input type="hidden" name="id" value={vuln.id} />
                <button
                  type="submit"
                  className={`${styles.btn} ${styles.btnDanger} ${styles.btnLg}`}
                >
                  Dismiss
                </button>
              </form>
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

        <div className={styles.panel}>
          <div className={styles.panelHeader}>
            <div className={styles.panelHeaderLeft}>
              <div className={styles.panelTitle}>
                Linked patches
                <span className={styles.panelCount}>({patches.length})</span>
              </div>
            </div>
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
