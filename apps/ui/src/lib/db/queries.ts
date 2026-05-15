// Postgres queries the UI's server components run directly.
//
// Architectural note: these queries are *read-only*. Mutations go through
// the API's /api/v1/* endpoints. We never UPDATE/INSERT/DELETE from the UI.
//
// Returned rows are typed to mirror src/types/index.ts. Numeric/Decimal
// columns come back as strings from postgres.js to avoid float precision
// loss; UI code formats them at the render site.

import { getSql } from "./index";
import type {
  Attack,
  Campaign,
  CostPerAgentRow,
  CostPerCampaignRow,
  CostTotals,
  CoverageRow,
  DashboardSummary,
  Patch,
  RegressionRun,
  Verdict,
  VulnerabilityDetail,
  VulnerabilityRow,
  VulnerabilitySeverity,
} from "@/types";

// The closed set of agent identities recognised by agent_traces.
// Mirrors the CHECK constraint in apps/api/alembic/versions/0002_core_schema.py
// (ck_agent_traces_agent). Kept alphabetical so the cost dashboard renders a
// stable row order even when zero-call agents are filled in client-side.
const AGENTS = [
  "documentation",
  "judge",
  "orchestrator",
  "patch",
  "red_team",
] as const;

// ---------------------------------------------------------------------------
// Campaigns
// ---------------------------------------------------------------------------

export async function listCampaigns(limit = 50): Promise<Campaign[]> {
  const sql = getSql();
  const rows = await sql<Campaign[]>`
    SELECT
      c.id::text,
      c.target_subcategory,
      c.status,
      c.mode,
      c.budget_usd::text,
      COALESCE(
        (SELECT SUM(at.cost_usd) FROM agent_traces at WHERE at.campaign_id = c.id),
        0
      )::text AS spent_usd,
      c.created_at,
      c.completed_at
    FROM campaigns c
    ORDER BY c.created_at DESC
    LIMIT ${limit}
  `;
  return rows;
}

export async function getCampaign(id: string): Promise<Campaign | null> {
  const sql = getSql();
  const rows = await sql<Campaign[]>`
    SELECT
      c.id::text,
      c.target_subcategory,
      c.status,
      c.mode,
      c.budget_usd::text,
      COALESCE(
        (SELECT SUM(at.cost_usd) FROM agent_traces at WHERE at.campaign_id = c.id),
        0
      )::text AS spent_usd,
      c.created_at,
      c.completed_at
    FROM campaigns c
    WHERE c.id = ${id}::uuid
    LIMIT 1
  `;
  return rows[0] ?? null;
}

export async function listAttacksForCampaign(
  campaignId: string,
  limit = 200
): Promise<Attack[]> {
  const sql = getSql();
  const rows = await sql<Attack[]>`
    SELECT
      id::text,
      campaign_id::text,
      category,
      subcategory,
      mutation_strategy,
      attack_input,
      target_response,
      target_response_status,
      status,
      created_at,
      executed_at
    FROM attacks
    WHERE campaign_id = ${campaignId}::uuid
    ORDER BY created_at ASC
    LIMIT ${limit}
  `;
  return rows;
}

export async function listVerdictsForAttacks(
  attackIds: string[]
): Promise<Map<string, Verdict>> {
  if (attackIds.length === 0) return new Map();
  const sql = getSql();
  const rows = await sql<Verdict[]>`
    SELECT
      id::text,
      attack_id::text,
      verdict,
      confidence::text,
      evidence,
      rubric_version,
      model_version,
      created_at
    FROM verdicts
    WHERE attack_id = ANY(${attackIds}::uuid[])
  `;
  const map = new Map<string, Verdict>();
  for (const v of rows) map.set(v.attack_id, v);
  return map;
}

/**
 * Find the most recent active campaign (in_progress or pending), if any.
 * Used by the dashboard hero badge to switch into ATTACK MODE.
 */
export async function getActiveCampaign(): Promise<Campaign | null> {
  const sql = getSql();
  const rows = await sql<Campaign[]>`
    SELECT
      c.id::text,
      c.target_subcategory,
      c.status,
      c.mode,
      c.budget_usd::text,
      COALESCE(
        (SELECT SUM(at.cost_usd) FROM agent_traces at WHERE at.campaign_id = c.id),
        0
      )::text AS spent_usd,
      c.created_at,
      c.completed_at
    FROM campaigns c
    WHERE c.status IN ('pending', 'in_progress')
    ORDER BY c.created_at DESC
    LIMIT 1
  `;
  return rows[0] ?? null;
}

/**
 * Count draft vulnerabilities awaiting operator review.
 */
export async function countDraftVulnerabilities(): Promise<number> {
  const sql = getSql();
  const [row] = await sql<{ n: number }[]>`
    SELECT COUNT(*)::int AS n
    FROM vulnerabilities
    WHERE status = 'draft'
  `;
  return row?.n ?? 0;
}

// ---------------------------------------------------------------------------
// Vulnerabilities
// ---------------------------------------------------------------------------

export async function listVulnerabilities(
  limit = 100
): Promise<VulnerabilityRow[]> {
  const sql = getSql();
  return sql<VulnerabilityRow[]>`
    SELECT
      id::text,
      vuln_id,
      attack_id::text,
      verdict_id::text,
      severity,
      title,
      status,
      owasp_llm_id,
      mitre_atlas_technique_id,
      hipaa_safeguard,
      created_at,
      EXISTS (
        SELECT 1
        FROM jsonb_array_elements(notes) AS n
        WHERE n->>'action' = 'dismiss'
      ) AS is_dismissed
    FROM vulnerabilities
    ORDER BY
      CASE severity
        WHEN 'critical' THEN 0
        WHEN 'high'     THEN 1
        WHEN 'medium'   THEN 2
        WHEN 'low'      THEN 3
      END,
      created_at DESC
    LIMIT ${limit}
  `;
}

export async function getVulnerability(
  id: string
): Promise<VulnerabilityDetail | null> {
  const sql = getSql();
  const rows = await sql<VulnerabilityDetail[]>`
    SELECT
      id::text,
      vuln_id,
      attack_id::text,
      verdict_id::text,
      severity,
      title,
      status,
      owasp_llm_id,
      mitre_atlas_technique_id,
      hipaa_safeguard,
      clinical_impact,
      reproduction_steps,
      observed_behavior,
      expected_behavior,
      recommended_remediation,
      framework_versions,
      notes,
      variant_count,
      created_at
    FROM vulnerabilities
    WHERE id = ${id}::uuid
    LIMIT 1
  `;
  return rows[0] ?? null;
}

// ---------------------------------------------------------------------------
// Regression runs
// ---------------------------------------------------------------------------

/**
 * Most recent regression_runs row for the given vulnerability, or null if no
 * regression sweep has run yet. The `verdicts` column is JSONB — postgres.js
 * returns it pre-parsed.
 */
export async function getLatestRegressionRun(
  vulnerabilityId: string
): Promise<RegressionRun | null> {
  const sql = getSql();
  // Filter to exploit_replay rows so the Before/After security panel doesn't
  // accidentally render a happy-path row (those have a separate UI panel).
  const rows = await sql<RegressionRun[]>`
    SELECT
      id::text,
      vulnerability_id::text,
      target_version_id::text,
      replay_count,
      verdicts,
      outcome,
      triggered_by,
      started_at,
      completed_at,
      kind
    FROM regression_runs
    WHERE vulnerability_id = ${vulnerabilityId}::uuid
      AND kind = 'exploit_replay'
    ORDER BY started_at DESC
    LIMIT 1
  `;
  return rows[0] ?? null;
}

/**
 * Most recent kind='happy_path' regression_runs row for the vulnerability,
 * if any. Written by harness/runner._flip_over_fit when an over-fit patch
 * is detected — surfaces "patch fixed security but broke legitimate
 * features" on the diff page.
 */
export async function getLatestHappyPathRun(
  vulnerabilityId: string
): Promise<RegressionRun | null> {
  const sql = getSql();
  const rows = await sql<RegressionRun[]>`
    SELECT
      id::text,
      vulnerability_id::text,
      target_version_id::text,
      replay_count,
      verdicts,
      outcome,
      triggered_by,
      started_at,
      completed_at,
      kind
    FROM regression_runs
    WHERE vulnerability_id = ${vulnerabilityId}::uuid
      AND kind = 'happy_path'
    ORDER BY started_at DESC
    LIMIT 1
  `;
  return rows[0] ?? null;
}

/**
 * The original attack + verdict tied to the vulnerability (via the
 * vulnerabilities.attack_id and vulnerabilities.verdict_id pointers). Returns
 * null if the vuln or its referenced rows are missing.
 */
export async function getOriginalAttackForVulnerability(
  vulnerabilityId: string
): Promise<{ attack: Attack; verdict: Verdict } | null> {
  const sql = getSql();
  const rows = await sql<
    (Attack & {
      v_id: string;
      v_attack_id: string;
      v_verdict: Verdict["verdict"];
      v_confidence: string;
      v_evidence: string;
      v_rubric_version: string;
      v_model_version: string;
      v_created_at: string;
    })[]
  >`
    SELECT
      a.id::text          AS id,
      a.campaign_id::text AS campaign_id,
      a.category,
      a.subcategory,
      a.mutation_strategy,
      a.attack_input,
      a.target_response,
      a.target_response_status,
      a.status,
      a.created_at,
      a.executed_at,
      vd.id::text         AS v_id,
      vd.attack_id::text  AS v_attack_id,
      vd.verdict          AS v_verdict,
      vd.confidence::text AS v_confidence,
      vd.evidence         AS v_evidence,
      vd.rubric_version   AS v_rubric_version,
      vd.model_version    AS v_model_version,
      vd.created_at       AS v_created_at
    FROM vulnerabilities vuln
    JOIN attacks  a  ON a.id  = vuln.attack_id
    JOIN verdicts vd ON vd.id = vuln.verdict_id
    WHERE vuln.id = ${vulnerabilityId}::uuid
    LIMIT 1
  `;
  const row = rows[0];
  if (!row) return null;
  const attack: Attack = {
    id: row.id,
    campaign_id: row.campaign_id,
    category: row.category,
    subcategory: row.subcategory,
    mutation_strategy: row.mutation_strategy,
    attack_input: row.attack_input,
    target_response: row.target_response,
    target_response_status: row.target_response_status,
    status: row.status,
    created_at: row.created_at,
    executed_at: row.executed_at,
  };
  const verdict: Verdict = {
    id: row.v_id,
    attack_id: row.v_attack_id,
    verdict: row.v_verdict,
    confidence: row.v_confidence,
    evidence: row.v_evidence,
    rubric_version: row.v_rubric_version,
    model_version: row.v_model_version,
    created_at: row.v_created_at,
  };
  return { attack, verdict };
}

/**
 * Count of regression_runs rows for a vulnerability. Used by the detail page
 * to decide whether to show the "View diff" link.
 */
export async function countRegressionRunsForVulnerability(
  vulnerabilityId: string
): Promise<number> {
  const sql = getSql();
  const [row] = await sql<{ n: number }[]>`
    SELECT COUNT(*)::int AS n
    FROM regression_runs
    WHERE vulnerability_id = ${vulnerabilityId}::uuid
  `;
  return row?.n ?? 0;
}

// ---------------------------------------------------------------------------
// Patches
// ---------------------------------------------------------------------------

export async function listPatches(limit = 100): Promise<Patch[]> {
  const sql = getSql();
  return sql<Patch[]>`
    SELECT
      p.id::text,
      p.vulnerability_id::text,
      v.vuln_id AS vuln_id,
      p.branch_name,
      p.pr_url,
      p.status,
      p.created_at,
      p.merged_at,
      p.attempt_number
    FROM patches p
    LEFT JOIN vulnerabilities v ON v.id = p.vulnerability_id
    ORDER BY
      CASE p.status
        WHEN 'awaiting_human_review' THEN 0
        WHEN 'merged'                THEN 1
        WHEN 'ci_failed'             THEN 2
        WHEN 'rejected'              THEN 3
        WHEN 'superseded'            THEN 4
        WHEN 'blocks_legit_features' THEN 5
      END,
      p.created_at DESC
    LIMIT ${limit}
  `;
}

export async function listPatchesForVulnerability(
  vulnerabilityId: string
): Promise<Patch[]> {
  const sql = getSql();
  return sql<Patch[]>`
    SELECT
      p.id::text,
      p.vulnerability_id::text,
      v.vuln_id AS vuln_id,
      p.branch_name,
      p.pr_url,
      p.status,
      p.created_at,
      p.merged_at,
      p.attempt_number
    FROM patches p
    LEFT JOIN vulnerabilities v ON v.id = p.vulnerability_id
    WHERE p.vulnerability_id = ${vulnerabilityId}::uuid
    ORDER BY p.created_at DESC
  `;
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

export async function coverageSnapshot(): Promise<CoverageRow[]> {
  // Dashboard counts only LIVE campaigns; smoke runs are excluded.
  const sql = getSql();
  return sql<CoverageRow[]>`
    SELECT
      t.category,
      t.subcategory,
      COALESCE(stats.attempts, 0)::int AS attempts,
      COALESCE(stats.exploits, 0)::int AS exploits,
      COALESCE(stats.partials, 0)::int AS partials,
      stats.last_attempted_at
    FROM attack_taxonomy t
    LEFT JOIN (
      SELECT
        a.subcategory,
        COUNT(*)                                                 AS attempts,
        COUNT(v.id) FILTER (WHERE v.verdict = 'exploit')         AS exploits,
        COUNT(v.id) FILTER (WHERE v.verdict = 'partial')         AS partials,
        MAX(a.created_at)                                        AS last_attempted_at
      FROM attacks a
      JOIN campaigns c    ON c.id = a.campaign_id
      LEFT JOIN verdicts v ON v.attack_id = a.id
      WHERE c.mode = 'live'
      GROUP BY a.subcategory
    ) stats ON stats.subcategory = t.subcategory
    ORDER BY t.category, t.subcategory
  `;
}

export async function dashboardSummary(): Promise<DashboardSummary> {
  const sql = getSql();

  const [coverage] = await sql<{ total: number; covered: number }[]>`
    SELECT
      (SELECT COUNT(*)::int FROM attack_taxonomy) AS total,
      (
        SELECT COUNT(DISTINCT a.subcategory)::int
        FROM attacks a
        JOIN campaigns c ON c.id = a.campaign_id
        WHERE c.mode = 'live'
      ) AS covered
  `;

  const sevRows = await sql<
    { severity: VulnerabilitySeverity; n: number }[]
  >`
    SELECT severity, COUNT(*)::int AS n
    FROM vulnerabilities
    WHERE status IN ('open', 'draft', 'regressed', 'unstable')
    GROUP BY severity
  `;
  const bySeverity: Record<VulnerabilitySeverity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const r of sevRows) bySeverity[r.severity] = r.n;

  const [patches] = await sql<{ n: number }[]>`
    SELECT COUNT(*)::int AS n
    FROM patches
    WHERE status = 'awaiting_human_review'
  `;

  const [cost] = await sql<{ total: string; last_24h: string }[]>`
    SELECT
      COALESCE(SUM(at.cost_usd), 0)::text AS total,
      COALESCE(
        SUM(at.cost_usd) FILTER (WHERE at.started_at > now() - INTERVAL '24 hours'),
        0
      )::text AS last_24h
    FROM agent_traces at
    JOIN campaigns c ON c.id = at.campaign_id
    WHERE c.mode = 'live'
  `;

  return {
    total_subcategories: coverage?.total ?? 0,
    covered_subcategories: coverage?.covered ?? 0,
    open_vulnerabilities_by_severity: bySeverity,
    pending_patches: patches?.n ?? 0,
    total_cost_usd: cost?.total ?? "0",
    last_24h_cost_usd: cost?.last_24h ?? "0",
  };
}

// ---------------------------------------------------------------------------
// Cost dashboard
// ---------------------------------------------------------------------------

/**
 * Top-line spend metrics: all-time spend, last-24h spend, last-24h call count,
 * and last-24h avg cost per call. All money/decimal columns are returned as
 * text to preserve precision (the project convention).
 */
export async function costTotals(): Promise<CostTotals> {
  const sql = getSql();
  const [row] = await sql<
    {
      total_usd: string;
      spent_24h_usd: string;
      calls_24h: number;
      avg_cost_24h_usd: string;
    }[]
  >`
    SELECT
      COALESCE(SUM(cost_usd), 0)::text AS total_usd,
      COALESCE(
        SUM(cost_usd) FILTER (WHERE started_at > now() - INTERVAL '24 hours'),
        0
      )::text AS spent_24h_usd,
      COUNT(*) FILTER (WHERE started_at > now() - INTERVAL '24 hours')::int
        AS calls_24h,
      COALESCE(
        SUM(cost_usd) FILTER (WHERE started_at > now() - INTERVAL '24 hours')
          / NULLIF(
              COUNT(*) FILTER (WHERE started_at > now() - INTERVAL '24 hours'),
              0
            ),
        0
      )::text AS avg_cost_24h_usd
    FROM agent_traces
  `;
  return (
    row ?? {
      total_usd: "0",
      spent_24h_usd: "0",
      calls_24h: 0,
      avg_cost_24h_usd: "0",
    }
  );
}

/**
 * Spend + latency aggregates per agent across all-time. Always returns one row
 * per agent in the closed set (zero-call agents are filled in with zeros) so
 * the table renders deterministically.
 */
export async function costPerAgent(): Promise<CostPerAgentRow[]> {
  const sql = getSql();
  const rows = await sql<
    {
      agent: string;
      calls: number;
      total_usd: string;
      avg_usd: string;
      p50_ms: number;
      p95_ms: number;
    }[]
  >`
    SELECT
      agent,
      COUNT(*)::int                                          AS calls,
      COALESCE(SUM(cost_usd), 0)::text                       AS total_usd,
      COALESCE(AVG(cost_usd), 0)::text                       AS avg_usd,
      COALESCE(
        percentile_cont(0.5)  WITHIN GROUP (ORDER BY duration_ms),
        0
      )::int                                                 AS p50_ms,
      COALESCE(
        percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms),
        0
      )::int                                                 AS p95_ms
    FROM agent_traces
    GROUP BY agent
  `;

  const byAgent = new Map<string, CostPerAgentRow>();
  for (const r of rows) byAgent.set(r.agent, r);

  return AGENTS.map(
    (agent): CostPerAgentRow =>
      byAgent.get(agent) ?? {
        agent,
        calls: 0,
        total_usd: "0",
        avg_usd: "0",
        p50_ms: 0,
        p95_ms: 0,
      }
  );
}

/**
 * Per-campaign spend rollup for the most recent N campaigns by start time.
 * Left-joined against agent_traces so campaigns with zero traces still appear.
 */
export async function costPerCampaign(
  limit = 20
): Promise<CostPerCampaignRow[]> {
  const sql = getSql();
  return sql<CostPerCampaignRow[]>`
    SELECT
      c.id::text                              AS campaign_id,
      c.target_subcategory                    AS target_subcategory,
      c.status                                AS status,
      COALESCE(SUM(at.cost_usd), 0)::text     AS total_usd,
      COUNT(at.id)::int                       AS calls,
      COALESCE(c.started_at, c.created_at)    AS started_at,
      c.completed_at                          AS completed_at
    FROM campaigns c
    LEFT JOIN agent_traces at ON at.campaign_id = c.id
    GROUP BY c.id, c.target_subcategory, c.status, c.started_at,
             c.created_at, c.completed_at
    ORDER BY COALESCE(c.started_at, c.created_at) DESC
    LIMIT ${limit}
  `;
}
