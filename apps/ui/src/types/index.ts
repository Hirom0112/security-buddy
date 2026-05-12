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
  | "unstable";

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
}

export interface VulnerabilityDetail extends VulnerabilityRow {
  clinical_impact: string;
  reproduction_steps: string;
  observed_behavior: string;
  expected_behavior: string;
  recommended_remediation: string;
  framework_versions: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Patches
// ---------------------------------------------------------------------------

export type PatchStatus =
  | "awaiting_human_review"
  | "merged"
  | "rejected"
  | "ci_failed";

export interface Patch {
  id: string;
  vulnerability_id: string;
  vuln_id: string | null;
  branch_name: string;
  pr_url: string;
  status: PatchStatus;
  created_at: string;
  merged_at: string | null;
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
