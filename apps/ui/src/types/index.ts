// Mirror of API domain types. Hand-maintained — bump when the Pydantic
// models in apps/api/src/domain/ change. Consider openapi-typescript if
// this grows beyond ~200 lines.

export interface HealthStatus {
  status: "ok" | "degraded" | "down";
  db: "ok" | "error";
  redis: "ok" | "error";
  langsmith: "ok" | "error";
  version: string;
}

export interface LoginFormState {
  error?: string | undefined;
}

// ---------------------------------------------------------------------------
// Campaigns
// ---------------------------------------------------------------------------

export type CampaignStatus =
  | "pending"
  | "in_progress"
  | "completed"
  | "halted"
  | "budget_warning"
  | "budget_exhausted"
  | "no_candidates";

export type CampaignMode = "live" | "smoke";

export interface Campaign {
  id: string;
  target_subcategory: string | null;
  status: CampaignStatus;
  mode: CampaignMode;
  budget_usd: string; // decimal as string
  spent_usd: string;
  created_at: string;
  completed_at: string | null;
}

// ---------------------------------------------------------------------------
// Attacks + Verdicts
// ---------------------------------------------------------------------------

export type AttackStatus =
  | "pending_execution"
  | "awaiting_judgment"
  | "judged"
  | "target_unavailable";

export interface Attack {
  id: string;
  campaign_id: string;
  category: string;
  subcategory: string;
  mutation_strategy: string;
  attack_input: string;
  target_response: string | null;
  target_response_status: number | null;
  status: AttackStatus;
  created_at: string;
  executed_at: string | null;
}

export type VerdictLabel = "safe" | "exploit" | "partial" | "unclear";

export interface Verdict {
  id: string;
  attack_id: string;
  verdict: VerdictLabel;
  confidence: string;
  evidence: string;
  rubric_version: string;
  model_version: string;
  created_at: string;
}

// ---------------------------------------------------------------------------
// Vulnerabilities
// ---------------------------------------------------------------------------

export type VulnerabilityStatus =
  | "draft"
  | "open"
  | "proposed_fix"
  | "patched"
  | "regressed"
  | "unstable"
  | "over_fit";

export type VulnerabilitySeverity = "critical" | "high" | "medium" | "low";

export interface VulnerabilityRow {
  id: string;
  vuln_id: string;
  attack_id: string;
  verdict_id: string;
  severity: VulnerabilitySeverity;
  title: string;
  status: VulnerabilityStatus;
  owasp_llm_id: string;
  mitre_atlas_technique_id: string;
  hipaa_safeguard: string;
  created_at: string;
  is_dismissed?: boolean;
}

export interface VulnerabilityNote {
  at: string;
  actor: string;
  action: string;
  reason: string;
}

export interface VulnerabilityDetail extends VulnerabilityRow {
  clinical_impact: string;
  reproduction_steps: string;
  observed_behavior: string;
  expected_behavior: string;
  recommended_remediation: string;
  framework_versions: Record<string, string>;
  notes: VulnerabilityNote[];
  /**
   * Number of sibling exploits merged into this finding via the Documentation
   * Agent's response-shape dedup. 1 = unique finding; >1 = canonical for a
   * cluster of look-alikes. See migration 0013 + workers/documentation_worker.
   */
  variant_count: number;
}

// ---------------------------------------------------------------------------
// Attack taxonomy (Start Campaign modal dropdowns)
// ---------------------------------------------------------------------------

export interface TaxonomyCategory {
  category: string;
  subcategories: string[];
}

export interface AttackTaxonomy {
  categories: TaxonomyCategory[];
}

export interface VulnerabilitySummary {
  id: string;
  vuln_id: string;
  title: string;
  status: VulnerabilityStatus;
  severity: VulnerabilitySeverity;
  subcategory: string;
}

export interface VulnerabilityListResponse {
  items: VulnerabilitySummary[];
  total: number;
}

// ---------------------------------------------------------------------------
// Wide Sweep
// ---------------------------------------------------------------------------

export type WideSweepBreadth = "critical" | "critical_plus_high" | "all";

export interface WideSweepResult {
  subcategories: string[];
  subcategory_count: number;
  estimated_total_usd: string;
  sweep_job_id: string;
  enqueued_at: string;
}

// ---------------------------------------------------------------------------
// Regression runs
// ---------------------------------------------------------------------------

export type RegressionOutcome =
  | "fix_verified"
  | "regressed"
  | "unstable"
  | "target_unavailable";

export interface RegressionReplay {
  verdict: VerdictLabel;
  evidence: string;
  target_status_code: number;
}

export interface RegressionRun {
  id: string;
  vulnerability_id: string;
  target_version_id: string;
  replay_count: number;
  verdicts: RegressionReplay[];
  outcome: RegressionOutcome;
  triggered_by: string;
  started_at: string;
  completed_at: string | null;
  kind?: "exploit_replay" | "happy_path";
}

// One per-fixture entry inside the verdicts JSONB column for a
// regression_runs row where kind='happy_path' — written by
// _flip_over_fit in src/harness/runner.py.
export interface HappyPathReplay {
  verdict: "happy_path_pass" | "happy_path_fail";
  evidence: string;
  target_status_code: number | null;
  capability_name: string;
  fixture_id: string;
}

// ---------------------------------------------------------------------------
// Patches
// ---------------------------------------------------------------------------

export type PatchStatus =
  | "awaiting_human_review"
  | "merged"
  | "rejected"
  | "ci_failed"
  | "blocks_legit_features"
  | "superseded";

export interface Patch {
  id: string;
  vulnerability_id: string;
  vuln_id: string | null;
  branch_name: string;
  pr_url: string;
  status: PatchStatus;
  created_at: string;
  merged_at: string | null;
  attempt_number: number;
}

// ---------------------------------------------------------------------------
// Dashboard aggregates
// ---------------------------------------------------------------------------

export interface CoverageRow {
  category: string;
  subcategory: string;
  attempts: number;
  exploits: number;
  partials: number;
  last_attempted_at: string | null;
}

export interface DashboardSummary {
  total_subcategories: number;
  covered_subcategories: number;
  open_vulnerabilities_by_severity: Record<VulnerabilitySeverity, number>;
  pending_patches: number;
  total_cost_usd: string;
  last_24h_cost_usd: string;
}

// ---------------------------------------------------------------------------
// Cost dashboard
// ---------------------------------------------------------------------------

export interface CostTotals {
  total_usd: string;
  spent_24h_usd: string;
  calls_24h: number;
  avg_cost_24h_usd: string;
}

export interface CostPerAgentRow {
  agent: string;
  calls: number;
  total_usd: string;
  avg_usd: string;
  p50_ms: number;
  p95_ms: number;
}

export interface CostPerCampaignRow {
  campaign_id: string;
  target_subcategory: string | null;
  status: string;
  total_usd: string;
  calls: number;
  started_at: string;
  completed_at: string | null;
}
