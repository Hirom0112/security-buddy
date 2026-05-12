// Severity + status badge utilities — small inline pills.

import { cn } from "@/lib/utils";
import type {
  CampaignStatus,
  PatchStatus,
  VerdictLabel,
  VulnerabilitySeverity,
  VulnerabilityStatus,
} from "@/types";

const SEV: Record<VulnerabilitySeverity, string> = {
  critical: "bg-red-100 text-red-900 border-red-300",
  high: "bg-orange-100 text-orange-900 border-orange-300",
  medium: "bg-yellow-100 text-yellow-900 border-yellow-300",
  low: "bg-slate-100 text-slate-700 border-slate-300",
};

export function SeverityBadge({ severity }: { severity: VulnerabilitySeverity }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium",
        SEV[severity]
      )}
    >
      {severity}
    </span>
  );
}

const VULN_STATUS: Record<VulnerabilityStatus, string> = {
  draft: "bg-amber-100 text-amber-900 border-amber-300",
  open: "bg-blue-100 text-blue-900 border-blue-300",
  proposed_fix: "bg-violet-100 text-violet-900 border-violet-300",
  patched: "bg-green-100 text-green-900 border-green-300",
  regressed: "bg-red-100 text-red-900 border-red-300",
  unstable: "bg-pink-100 text-pink-900 border-pink-300",
};

export function VulnStatusBadge({ status }: { status: VulnerabilityStatus }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium",
        VULN_STATUS[status]
      )}
    >
      {status.replace("_", " ")}
    </span>
  );
}

const PATCH_STATUS: Record<PatchStatus, string> = {
  awaiting_human_review: "bg-amber-100 text-amber-900 border-amber-300",
  merged: "bg-green-100 text-green-900 border-green-300",
  rejected: "bg-slate-200 text-slate-700 border-slate-300",
  ci_failed: "bg-red-100 text-red-900 border-red-300",
};

export function PatchStatusBadge({ status }: { status: PatchStatus }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium",
        PATCH_STATUS[status]
      )}
    >
      {status.replace(/_/g, " ")}
    </span>
  );
}

const CAMPAIGN_STATUS: Record<CampaignStatus, string> = {
  pending: "bg-slate-100 text-slate-700 border-slate-300",
  in_progress: "bg-blue-100 text-blue-900 border-blue-300",
  completed: "bg-green-100 text-green-900 border-green-300",
  halted: "bg-orange-100 text-orange-900 border-orange-300",
  budget_warning: "bg-yellow-100 text-yellow-900 border-yellow-300",
  budget_exhausted: "bg-red-100 text-red-900 border-red-300",
  no_candidates: "bg-slate-200 text-slate-700 border-slate-300",
};

export function CampaignStatusBadge({ status }: { status: CampaignStatus }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium",
        CAMPAIGN_STATUS[status]
      )}
    >
      {status.replace(/_/g, " ")}
    </span>
  );
}

const VERDICT: Record<VerdictLabel, string> = {
  safe: "bg-green-100 text-green-900 border-green-300",
  exploit: "bg-red-100 text-red-900 border-red-300",
  partial: "bg-orange-100 text-orange-900 border-orange-300",
  unclear: "bg-slate-100 text-slate-700 border-slate-300",
};

export function VerdictBadge({ verdict }: { verdict: VerdictLabel }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium",
        VERDICT[verdict]
      )}
    >
      {verdict}
    </span>
  );
}
