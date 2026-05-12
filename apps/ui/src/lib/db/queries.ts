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
  CoverageRow,
  DashboardSummary,
  Patch,
  Verdict,
  VulnerabilityDetail,
  VulnerabilityRow,
  VulnerabilitySeverity,
} from "@/types";

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
      created_at
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
      created_at
    FROM vulnerabilities
    WHERE id = ${id}::uuid
    LIMIT 1
  `;
  return rows[0] ?? null;
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
      p.merged_at
    FROM patches p
    LEFT JOIN vulnerabilities v ON v.id = p.vulnerability_id
    ORDER BY
      CASE p.status
        WHEN 'awaiting_human_review' THEN 0
        WHEN 'merged'                THEN 1
        WHEN 'ci_failed'             THEN 2
        WHEN 'rejected'              THEN 3
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
      p.merged_at
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
