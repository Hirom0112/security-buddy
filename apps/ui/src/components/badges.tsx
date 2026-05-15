// Severity + status badge utilities — dark-themed cyber-noir pills.

import { cn } from "@/lib/utils";
import type {
  CampaignStatus,
  PatchStatus,
  VerdictLabel,
  VulnerabilitySeverity,
  VulnerabilityStatus,
} from "@/types";

const BASE =
  "inline-flex items-center rounded border px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider";

// Tone presets keyed by accent color. Backgrounds are translucent over the
// dark surface so the badge picks up the underlying panel color.
const TONE = {
  neon: "border-[#00f5c4]/40 bg-[#00f5c4]/10 text-[#00f5c4]",
  danger: "border-[#ff3d6b]/40 bg-[#ff3d6b]/10 text-[#ff3d6b]",
  warn: "border-[#ffb830]/40 bg-[#ffb830]/10 text-[#ffb830]",
  purple: "border-[#7c3aed]/40 bg-[#7c3aed]/10 text-[#a78bfa]",
  pink: "border-pink-500/40 bg-pink-500/10 text-pink-300",
  blue: "border-sky-400/40 bg-sky-400/10 text-sky-300",
  green: "border-emerald-400/40 bg-emerald-400/10 text-emerald-300",
  muted: "border-slate-600/50 bg-slate-700/30 text-slate-300",
} as const;

const SEV: Record<VulnerabilitySeverity, string> = {
  critical: TONE.danger,
  high: TONE.warn,
  medium: TONE.purple,
  low: TONE.muted,
};

export function SeverityBadge({
  severity,
}: {
  severity: VulnerabilitySeverity;
}) {
  return <span className={cn(BASE, SEV[severity])}>{severity}</span>;
}

const VULN_STATUS: Record<VulnerabilityStatus, string> = {
  draft: TONE.warn,
  open: TONE.blue,
  proposed_fix: TONE.purple,
  patched: TONE.green,
  regressed: TONE.danger,
  unstable: TONE.pink,
  over_fit: TONE.warn,
};

export function VulnStatusBadge({ status }: { status: VulnerabilityStatus }) {
  return (
    <span className={cn(BASE, VULN_STATUS[status])}>
      {status.replace("_", " ")}
    </span>
  );
}

const PATCH_STATUS: Record<PatchStatus, string> = {
  awaiting_human_review: TONE.warn,
  merged: TONE.green,
  rejected: TONE.muted,
  ci_failed: TONE.danger,
  blocks_legit_features: TONE.warn,
};

export function PatchStatusBadge({ status }: { status: PatchStatus }) {
  return (
    <span className={cn(BASE, PATCH_STATUS[status])}>
      {status.replace(/_/g, " ")}
    </span>
  );
}

const CAMPAIGN_STATUS: Record<CampaignStatus, string> = {
  pending: TONE.muted,
  in_progress: TONE.blue,
  completed: TONE.green,
  halted: TONE.warn,
  budget_warning: TONE.warn,
  budget_exhausted: TONE.danger,
  no_candidates: TONE.muted,
};

export function CampaignStatusBadge({ status }: { status: CampaignStatus }) {
  return (
    <span className={cn(BASE, CAMPAIGN_STATUS[status])}>
      {status.replace(/_/g, " ")}
    </span>
  );
}

const VERDICT: Record<VerdictLabel, string> = {
  safe: TONE.green,
  exploit: TONE.danger,
  partial: TONE.warn,
  unclear: TONE.muted,
};

export function VerdictBadge({ verdict }: { verdict: VerdictLabel }) {
  return <span className={cn(BASE, VERDICT[verdict])}>{verdict}</span>;
}
