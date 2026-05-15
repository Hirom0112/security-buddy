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
  getLatestHappyPathRun,
  getLatestRegressionRun,
  getOriginalAttackForVulnerability,
  getVulnerability,
} from "@/lib/db/queries";
import styles from "@/app/dashboard.module.css";
import type {
  HappyPathReplay,
  RegressionOutcome,
  RegressionReplay,
  RegressionRun,
  VerdictLabel,
} from "@/types";

// Banner status code — derived from (exploit-outcome, happy-path-outcome,
// vuln-status). OVER_FIT is a fourth state distinct from REGRESSED /
// RESOLVED / UNSTABLE: the security fix held but the patch broke a legit
// capability.
type BannerCode =
  | "fix_verified"
  | "regressed"
  | "unstable"
  | "target_unavailable"
  | "over_fit";

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
  BannerCode,
  { label: string; accent: string; color: string }
> = {
  fix_verified: {
    label: "RESOLVED",
    accent: "var(--sb-ok)",
    color: "var(--sb-ok)",
  },
  regressed: {
    label: "SECURITY REGRESSED",
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
  over_fit: {
    label: "OVER_FIT — PATCH BROKE LEGIT FEATURE",
    accent: "var(--sb-warn)",
    color: "var(--sb-warn)",
  },
};

function pickBanner(
  exploitOutcome: RegressionOutcome,
  happyPathFailed: boolean
): BannerCode {
  // Over-fit takes precedence — a patch that resolved the exploit but
  // broke a legitimate capability is the most actionable signal.
  if (happyPathFailed) return "over_fit";
  return exploitOutcome;
}

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

  const [latest, original, happyPath] = await Promise.all([
    getLatestRegressionRun(id),
    getOriginalAttackForVulnerability(id),
    getLatestHappyPathRun(id),
  ]);

  const happyPathFailed =
    happyPath !== null &&
    happyPath.verdicts.some(
      (v) => (v as unknown as HappyPathReplay).verdict === "happy_path_fail"
    );
  const banner: BannerCode | null =
    latest === null ? null : pickBanner(latest.outcome, happyPathFailed);

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
          <StatusBanner code={banner ?? latest.outcome} />
          <div className={styles.diffGrid} style={{ marginTop: 20 }}>
            <BeforePanel
              vulnTitle={vuln.title}
              vulnId={vuln.vuln_id}
              severity={vuln.severity}
              original={original}
            />
            <AfterPanel run={latest} />
          </div>
          {happyPath !== null && (
            <HappyPathPanel run={happyPath} />
          )}
        </>
      )}
    </ThemedShell>
  );
}

function StatusBanner({ code }: { code: BannerCode }) {
  const meta = OUTCOME_META[code];
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
        {code === "fix_verified" &&
          "Latest regression sweep confirms the exploit no longer reproduces. The patch held."}
        {code === "regressed" &&
          "Latest regression sweep reproduced the original exploit. The patch did not hold."}
        {code === "unstable" &&
          "Latest regression sweep produced mixed verdicts across replays. The fix is not consistently effective."}
        {code === "target_unavailable" &&
          "Target was unreachable during the regression sweep — no verdict could be reached."}
        {code === "over_fit" &&
          "Security boundary held, but the patch broke at least one legitimate clinician capability. See the happy-path panel below."}
      </p>
    </div>
  );
}

function HappyPathPanel({ run }: { run: RegressionRun }) {
  // The harness stores per-fixture rows inside the verdicts JSONB column
  // when kind='happy_path'. Cast through unknown — the column union is
  // intentionally wider than HappyPathReplay so the existing
  // RegressionReplay path stays valid.
  const fixtures = run.verdicts as unknown as HappyPathReplay[];
  const failed = fixtures.filter((f) => f.verdict === "happy_path_fail");
  const passed = fixtures.filter((f) => f.verdict === "happy_path_pass");
  return (
    <div className={styles.panel} style={{ marginTop: 20 }}>
      <div className={styles.panelHeader}>
        <div className={styles.panelHeaderLeft}>
          <div className={styles.panelTitle}>
            Happy-path replay results
          </div>
        </div>
      </div>
      <div className={styles.panelBody}>
        <div className={styles.diffAggregate}>
          <span>
            <strong>{fixtures.length}</strong> fixtures
          </span>
          <span>
            · <strong>{passed.length}</strong> pass
          </span>
          <span>
            · <strong>{failed.length}</strong> fail
          </span>
        </div>
        <div className={styles.diffPanelMetaRow}>
          <span className={styles.dataMuted}>
            run {new Date(run.started_at).toLocaleString()}
          </span>
          <span className={styles.dataMuted}>
            · triggered by {run.triggered_by}
          </span>
        </div>
        {fixtures.length === 0 ? (
          <div className={styles.panelEmpty}>
            No happy-path fixtures were evaluated.
          </div>
        ) : (
          <ul className={styles.replayList}>
            {fixtures.map((f, i) => (
              <li key={i} className={styles.replayItem}>
                <div className={styles.replayHead}>
                  <span className={styles.replayIndex}>
                    {f.capability_name}
                  </span>
                  <span
                    style={{
                      color:
                        f.verdict === "happy_path_pass"
                          ? "var(--sb-ok)"
                          : "var(--sb-danger)",
                    }}
                  >
                    {f.verdict === "happy_path_pass" ? "PASS" : "FAIL"}
                  </span>
                  {f.target_status_code !== null && (
                    <span>HTTP {f.target_status_code}</span>
                  )}
                </div>
                <pre className={styles.replayEvidence}>{f.evidence}</pre>
              </li>
            ))}
          </ul>
        )}
      </div>
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
