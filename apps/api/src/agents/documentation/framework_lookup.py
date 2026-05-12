"""Resolve framework citations from attack_taxonomy for the source subcategory.

CLAUDE.md §6a — framework versions are snapshotted at confirmation time. The
LLM never invents framework IDs. This module reads them from the
attack_taxonomy row and returns a FrameworkCitation the worker writes into
the vulnerabilities row.
"""

from typing import Any

from src.agents.documentation.schema import FrameworkCitation


class FrameworkLookupError(ValueError):
    """Raised when framework_mappings or framework_versions are missing/malformed."""


def resolve_citation(
    *,
    framework_mappings: dict[str, Any],
    framework_versions: dict[str, Any],
) -> FrameworkCitation:
    """Build a FrameworkCitation from the taxonomy row's JSONB fields.

    Args:
        framework_mappings: attack_taxonomy.framework_mappings, e.g.
            {"owasp_llm": "LLM01:2025",
             "mitre_atlas": "AML.T0051.001",
             "hipaa": ["164.312(a)(1)", "164.312(c)(1)"]}.
        framework_versions: attack_taxonomy.framework_versions, e.g.
            {"owasp_llm": "2025-v2.0", "mitre_atlas": "5.1.0",
             "hipaa": "2013-omnibus"}.

    The hipaa field in framework_mappings may be a string or a list of
    strings; we always render it as a comma-separated string for the DB
    column (which is plain text — list semantics would be schema bloat).
    """
    owasp = framework_mappings.get("owasp_llm")
    atlas = framework_mappings.get("mitre_atlas")
    hipaa = framework_mappings.get("hipaa")

    if not isinstance(owasp, str) or not owasp.strip():
        raise FrameworkLookupError("framework_mappings.owasp_llm missing")
    if not isinstance(atlas, str) or not atlas.strip():
        raise FrameworkLookupError("framework_mappings.mitre_atlas missing")

    if isinstance(hipaa, list):
        hipaa_str = ", ".join(str(h) for h in hipaa if str(h).strip())
        if not hipaa_str:
            raise FrameworkLookupError("framework_mappings.hipaa missing or empty")
    elif isinstance(hipaa, str) and hipaa.strip():
        hipaa_str = hipaa
    else:
        raise FrameworkLookupError("framework_mappings.hipaa missing or empty")

    if not isinstance(framework_versions, dict) or not framework_versions:
        raise FrameworkLookupError("framework_versions missing or empty")

    # Normalize all version values to strings; the JSONB column could store
    # anything but downstream consumers (regression harness) expect strings.
    versions_str: dict[str, str] = {
        k: str(v) for k, v in framework_versions.items() if v is not None
    }

    return FrameworkCitation(
        owasp_llm_id=owasp,
        mitre_atlas_technique_id=atlas,
        hipaa_safeguard=hipaa_str,
        framework_versions=versions_str,
    )
