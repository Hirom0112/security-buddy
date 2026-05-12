"""Patch-Agent prompts: code search and diff generation.

These prompts are kept deterministic and pure (no I/O) so they're trivially
unit-testable. The Patch Agent does not clone the OpenEMR repo in Slice 5 —
candidate file paths come from the LLM's knowledge of the OpenEMR codebase
plus the surface description in the vulnerability report. The reviewer
verifies correctness at PR review time.
"""

from __future__ import annotations

from src.llm_client.types import Message


def build_file_selection_messages(
    *,
    title: str,
    clinical_impact: str,
    reproduction_steps: str,
    observed_behavior: str,
    expected_behavior: str,
    recommended_remediation: str,
    owasp_llm_id: str,
    repo_slug: str,
) -> list[Message]:
    """Build the prompt that asks the LLM to nominate target file paths.

    The LLM returns FileSelection JSON: a list of candidate relative paths
    in the OpenEMR fork plus a one-paragraph rationale.
    """
    system = (
        "You are a senior application security engineer reviewing a confirmed "
        "vulnerability in a deployed OpenEMR fork. Your job in this step is "
        "narrow: name the relative file paths most likely to need editing.\n\n"
        f"Repository: {repo_slug}\n"
        "Output STRICT JSON matching this schema (no prose, no fences):\n"
        '{"file_paths": ["..."], "reasoning": "..."}\n'
        "Constraints:\n"
        "- 1 to 5 file paths.\n"
        "- Paths must be relative to repo root and use forward slashes.\n"
        "- Prefer the smallest change surface that addresses the report.\n"
        "- If unsure, list your best guess and explain the uncertainty in "
        "reasoning."
    )

    user = (
        f"# Vulnerability\n"
        f"**Title:** {title}\n\n"
        f"**OWASP LLM:** {owasp_llm_id}\n\n"
        f"**Clinical impact:**\n{clinical_impact}\n\n"
        f"**Reproduction steps:**\n{reproduction_steps}\n\n"
        f"**Observed behavior:**\n{observed_behavior}\n\n"
        f"**Expected behavior:**\n{expected_behavior}\n\n"
        f"**Recommended remediation:**\n{recommended_remediation}\n\n"
        "Return the FileSelection JSON now."
    )

    return [
        Message(role="system", content=system),
        Message(role="user", content=user),
    ]


def build_patch_draft_messages(
    *,
    title: str,
    clinical_impact: str,
    reproduction_steps: str,
    recommended_remediation: str,
    owasp_llm_id: str,
    mitre_atlas_technique_id: str,
    hipaa_safeguard: str,
    vuln_id: str,
    repo_slug: str,
    candidate_paths: list[str],
) -> list[Message]:
    """Build the prompt that asks the LLM to write a patch.

    Output is PatchDraft JSON: commit_message, pr_title, pr_body,
    justification, files=[{path, contents}].
    """
    paths_block = "\n".join(f"- {p}" for p in candidate_paths) or "- (none)"

    system = (
        "You are a senior application security engineer writing a code patch "
        "for a confirmed vulnerability in a deployed OpenEMR fork. The "
        "patch will be opened as a GitHub PR, reviewed by a human operator, "
        "and merged only after approval. Branch protection is enforced on "
        "the fork.\n\n"
        f"Repository: {repo_slug}\n"
        "Output STRICT JSON matching this schema (no prose, no fences):\n"
        "{\n"
        '  "commit_message": "...",\n'
        '  "pr_title": "...",\n'
        '  "pr_body": "...",\n'
        '  "justification": "...",\n'
        '  "files": [{"path": "...", "contents": "..."}]\n'
        "}\n"
        "Constraints:\n"
        "- 1 to 5 files. Each `contents` is the FULL new file contents.\n"
        "- The PR body MUST cite the OWASP LLM ID, MITRE ATLAS technique, "
        "and the originating vulnerability ID.\n"
        "- The PR body MUST include a 'Reviewer checklist' section.\n"
        "- The commit_message is one line, conventional-commit style "
        "(`fix(security): ...`).\n"
        "- Do NOT include test code or unrelated cleanup. Smallest possible "
        "change surface that addresses the report."
    )

    user = (
        f"# Vulnerability {vuln_id}\n"
        f"**Title:** {title}\n\n"
        f"**OWASP LLM:** {owasp_llm_id} | **MITRE ATLAS:** "
        f"{mitre_atlas_technique_id} | **HIPAA:** {hipaa_safeguard}\n\n"
        f"**Clinical impact:**\n{clinical_impact}\n\n"
        f"**Reproduction steps:**\n{reproduction_steps}\n\n"
        f"**Recommended remediation:**\n{recommended_remediation}\n\n"
        f"## Candidate files\nThe code-search step nominated these files:\n"
        f"{paths_block}\n\n"
        "Return the PatchDraft JSON now."
    )

    return [
        Message(role="system", content=system),
        Message(role="user", content=user),
    ]
