// Before/After diff view — compares the original confirmed exploit against
// the latest regression sweep replays after a patch merge. Server component;
// reads Postgres directly via lib/db/queries.

import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { getSession } from "@/lib/auth/session";
import { ThemedShell } from "@/components/themed-shell";
import {
  SeverityBadge,
  VerdictBadge,
  VulnStatusBadge,
} from "@/components/badges";
import {
  getLatestRegressionRun,
  getOriginalAttackForVulnerability,
  getVulnerability,
} from "@/lib/db/queries";
import styles from "@/app/dashboard.module.css";
import type {
  RegressionOutcome,
  RegressionReplay,
  VerdictLabel,
} from "@/types";

export const dynamic = "force-dynamic";

interface PageProps {
  params: Promise<{ id: string }>;
}

// Cap on rendered response text to keep the page render cheap and the DOM
// reasonable. Anything longer is truncated with an explicit marker.
const RESPONSE_TRUNCATE_AT = 4000;

function truncate(s: string | null, max: number): string {
  if (s === null) return "(no response captured)";
  if (s.length <= max) return s;
  return `${s.slice(0, max)}\n\n[truncated — ${s.length - max} more chars]`;
}

const OUTCOME_META: Record<
  RegressionOutcome,
  { label: string; accent: string; color: string }
> = {
  fix_verified: {
    label: "RESOLVED",
    accent: "var(--sb-ok)",
    color: "var(--sb-ok)",
  },
  regressed: {
    label: "REGRESSED",
    accent: "var(--sb-danger)",
    color: "var(--sb-danger)",
  },
  unstable: {
    label: "UNSTABLE",
    accent: "var(--sb-warn)",
    color: "var(--sb-warn)",
  },
  target_unavailable: {
    label: "TARGET UNAVAILABLE",
    accent: "var(--sb-muted)",
    color: "var(--sb-muted)",
  },
};

function tallyReplays(
  verdicts: RegressionReplay[]
): Record<VerdictLabel, number> {
  const tally: Record<VerdictLabel, number> = {
    safe: 0,
    exploit: 0,
    partial: 0,
    unclear: 0,
  };
  for (const r of verdicts) tally[r.verdict] += 1;
  return tally;
}

export default async function VulnerabilityDiffPage({ params }: PageProps) {
  const session = await getSession();
  if (session === null) redirect("/login");

  const { id } = await params;
  const vuln = await getVulnerability(id);
  if (vuln === null) notFound();

  const [latest, original] = await Promise.all([
    getLatestRegressionRun(id),
    getOriginalAttackForVulnerability(id),
  ]);

  return (
    <ThemedShell
      eyebrow={`// ${vuln.vuln_id} · DIFF`}
      title={`Before / After — ${vuln.title}`}
      meta={
        <>
          <SeverityBadge severity={vuln.severity} />
          <VulnStatusBadge status={vuln.status} />
        </>
      }
    >
      <Link href={`/vulnerabilities/${id}`} className={styles.diffBackLink}>
        {"← Back to vulnerability"}
      </Link>

      {latest === null ? (
        <div
          className={styles.alertCallout}
          style={{ ["--accent" as string]: "var(--sb-muted)" }}
        >
          <div className={styles.alertCalloutHeader}>
            <span className={styles.alertCalloutTitle}>
              No regression sweep
            </span>
          </div>
          <p className={styles.alertCalloutBody}>
            No regression sweep has run for this vulnerability yet. Once a
            patch is merged the Harness will replay the original exploit and
            the comparison will appear here.
          </p>
        </div>
      ) : (
        <>
          <StatusBanner outcome={latest.outcome} />
          <div className={styles.diffGrid} style={{ marginTop: 20 }}>
            <BeforePanel
              vulnTitle={vuln.title}
              vulnId={vuln.vuln_id}
              severity={vuln.severity}
              original={original}
            />
            <AfterPanel run={latest} />
          </div>
        </>
      )}
    </ThemedShell>
  );
}

function StatusBanner({ outcome }: { outcome: RegressionOutcome }) {
  const meta = OUTCOME_META[outcome];
  return (
    <div
      className={styles.alertCallout}
      style={{ ["--accent" as string]: meta.accent }}
    >
      <div className={styles.alertCalloutHeader}>
        <span
          className={styles.pulseDot}
          style={{ ["--accent" as string]: meta.accent }}
          aria-hidden="true"
        />
        <span
          className={styles.alertCalloutTitle}
          style={{ color: meta.color }}
        >
          {meta.label}
        </span>
      </div>
      <p className={styles.alertCalloutBody}>
        {outcome === "fix_verified" &&
          "Latest regression sweep confirms the exploit no longer reproduces. The patch held."}
        {outcome === "regressed" &&
          "Latest regression sweep reproduced the original exploit. The patch did not hold."}
        {outcome === "unstable" &&
          "Latest regression sweep produced mixed verdicts across replays. The fix is not consistently effective."}
        {outcome === "target_unavailable" &&
          "Target was unreachable during the regression sweep — no verdict could be reached."}
      </p>
    </div>
  );
}

function BeforePanel({
  vulnTitle,
  vulnId,
  severity,
  original,
}: {
  vulnTitle: string;
  vulnId: string;
  severity: import("@/types").VulnerabilitySeverity;
  original: Awaited<ReturnType<typeof getOriginalAttackForVulnerability>>;
}) {
  return (
    <div className={styles.panel}>
      <div className={styles.panelHeader}>
        <div className={styles.panelHeaderLeft}>
          <div className={styles.panelTitle}>BEFORE — original exploit</div>
        </div>
      </div>
      <div className={styles.panelBody}>
        <div className={styles.diffPanelMetaRow}>
          <span className={styles.dataMuted}>{vulnId}</span>
          <SeverityBadge severity={severity} />
          <span className={styles.dataMuted}>{vulnTitle}</span>
        </div>

        {original === null ? (
          <div className={styles.panelEmpty}>
            Original attack/verdict rows could not be loaded.
          </div>
        ) : (
          <>
            <div className={styles.diffSubHead}>Attack input</div>
            <pre className={styles.codeBlock}>
              {original.attack.attack_input}
            </pre>

            <div className={styles.diffSubHead}>Target response</div>
            <pre className={styles.codeBlock}>
              {truncate(original.attack.target_response, RESPONSE_TRUNCATE_AT)}
            </pre>

            <div className={styles.diffSubHead}>Judge verdict</div>
            <div className={styles.diffPanelMetaRow}>
              <VerdictBadge verdict={original.verdict.verdict} />
              <span className={styles.dataMuted}>
                confidence {original.verdict.confidence}
              </span>
            </div>
            <pre className={styles.codeBlock}>
              {original.verdict.evidence}
            </pre>
          </>
        )}
      </div>
    </div>
  );
}

function AfterPanel({
  run,
}: {
  run: NonNullable<Awaited<ReturnType<typeof getLatestRegressionRun>>>;
}) {
  const tally = tallyReplays(run.verdicts);
  const total = run.verdicts.length;
  const timestamp = run.completed_at ?? run.started_at;

  return (
    <div className={styles.panel}>
      <div className={styles.panelHeader}>
        <div className={styles.panelHeaderLeft}>
          <div className={styles.panelTitle}>
            AFTER — latest regression sweep
          </div>
        </div>
      </div>
      <div className={styles.panelBody}>
        <div className={styles.diffAggregate}>
          <span>
            <strong>{total}</strong> replays
          </span>
          <span>
            · <strong>{tally.safe}</strong> safe
          </span>
          <span>
            · <strong>{tally.exploit}</strong> exploit
          </span>
          <span>
            · <strong>{tally.partial}</strong> partial
          </span>
          <span>
            · <strong>{tally.unclear}</strong> unclear
          </span>
        </div>

        <div className={styles.diffPanelMetaRow}>
          <span className={styles.dataMuted}>
            run {new Date(timestamp).toLocaleString()}
          </span>
          <span className={styles.dataMuted}>· triggered by {run.triggered_by}</span>
        </div>

        {run.verdicts.length === 0 ? (
          <div className={styles.panelEmpty}>
            No replays were recorded for this sweep.
          </div>
        ) : (
          <ul className={styles.replayList}>
            {run.verdicts.map((r, i) => (
              <li key={i} className={styles.replayItem}>
                <div className={styles.replayHead}>
                  <span className={styles.replayIndex}>replay #{i + 1}</span>
                  <VerdictBadge verdict={r.verdict} />
                  <span>HTTP {r.target_status_code}</span>
                </div>
                <pre className={styles.replayEvidence}>{r.evidence}</pre>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
