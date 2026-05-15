"""Markdown report template.

The Documentation Agent persists structured columns in the vulnerabilities
row AND renders them into a single Markdown document for the UI's
copy-to-clipboard / GitHub-PR-body workflow. This module is responsible for
the deterministic rendering — same inputs always produce the same Markdown.

CLAUDE.md §6a / Slice 4 deliverables: every report references the framework
IDs directly in the title and remediation section so the report is
ingestible by a GRC system without manual translation.
"""

from src.agents.documentation.schema import (
    FrameworkCitation,
    Severity,
    VulnerabilityDraft,
)

_SEVERITY_BADGE: dict[Severity, str] = {
    Severity.CRITICAL: "[CRITICAL]",
    Severity.HIGH: "[HIGH]",
    Severity.MEDIUM: "[MEDIUM]",
    Severity.LOW: "[LOW]",
}


def render_title(*, draft: VulnerabilityDraft, citation: FrameworkCitation) -> str:
    """Return the report title with framework IDs appended in brackets.

    Example:
        "Cross-patient PHI exfiltration via PDF metadata injection
         [LLM01:2025 / AML.T0051.001 / HIPAA §164.312(a)(1)]"
    """
    hipaa_label = citation.hipaa_safeguard
    if not hipaa_label.startswith("HIPAA"):
        hipaa_label = f"HIPAA §{hipaa_label}"
    suffix = f"[{citation.owasp_llm_id} / {citation.mitre_atlas_technique_id} / {hipaa_label}]"
    return f"{draft.title} {suffix}"


def render_markdown(
    *,
    vuln_id: str,
    draft: VulnerabilityDraft,
    citation: FrameworkCitation,
    subcategory: str,
    final_severity: Severity,
    target_version: str | None,
) -> str:
    """Return the full Markdown report.

    Sections (Slice 4 DoD / ARCHITECTURE.md §3.4):
      Title (with framework IDs)
      Severity badge + vuln_id
      Clinical Impact
      Reproduction Steps
      Observed vs Expected
      Recommended Remediation (references framework IDs)
      Framework citation block with versions
    """
    title = render_title(draft=draft, citation=citation)
    badge = _SEVERITY_BADGE[final_severity]
    versions_lines = "\n".join(
        f"  - {k}: {v}" for k, v in sorted(citation.framework_versions.items())
    )
    target_line = f"**Target version:** `{target_version}`\n" if target_version else ""

    return f"""# {title}

**{badge}** · `{vuln_id}` · subcategory `{subcategory}`
{target_line}
## Clinical Impact

{draft.clinical_impact.strip()}

## Reproduction Steps

{draft.reproduction_steps.strip()}

## Observed Behavior

{draft.observed_behavior.strip()}

## Expected Behavior

{draft.expected_behavior.strip()}

## Recommended Remediation

{draft.recommended_remediation.strip()}

The remediation should bring the system back into compliance with:
- OWASP LLM Top 10 — `{citation.owasp_llm_id}`
- MITRE ATLAS — `{citation.mitre_atlas_technique_id}`
- HIPAA Security Rule — `{citation.hipaa_safeguard}`

## Framework Versions Snapshot

{versions_lines}

_Versions are snapshotted at confirmation time so regression replays
adjudicate against the same rubric era (CLAUDE.md §6a)._
"""
