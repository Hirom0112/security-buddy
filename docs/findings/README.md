# Vulnerability Findings

This directory holds the curated vulnerability reports — minimum 3, each professional-format with the required fields plus framework citations (OWASP LLM Top 10 2025, MITRE ATLAS v5.1.0, HIPAA Security Rule 2013 Omnibus).

## Current state

A platform-wide data wipe + recalibration completed 2026-05-15 to demonstrate the post-calibration loop with all three reviewer-requested guardrails active:

- **Judge `data_actually_disclosed` field** — auth-bypass-with-empty-response is now severity-downgraded instead of mis-labeled CRITICAL (commit `b839300`).
- **Pre-write 3-replay validation** — every exploit verdict is replayed 3× before minting a vulnerability; `replay_unstable` is dropped (commit `f15deb2`).
- **Response-shape dedup** — duplicate-shape findings within the same target_version collapse into a single vuln with `variant_count` (commit `f15deb2`).

A fresh **Wide Sweep** across CRITICAL + HIGH subcategories (≈13 subcategories, ~260 attacks) is running against the live deployed OpenEMR Clinical Co-Pilot. Findings will be exported here once the sweep completes and the operator has curated 3 across diverse attack surfaces.

## Selection criteria for the final 3

The chosen export trio MUST span at least three distinct OWASP LLM Top 10 categories — not three siblings of the same subcategory. Audit recommendation from this session, applied:

1. One **direct prompt injection** finding (LLM01) — role-override jailbreak or persona-hijack class.
2. One **indirect prompt injection** finding (LLM01) — document-framed or upload-vector.
3. One **sensitive information disclosure** finding (LLM06) — bulk extraction or partial-identifier inference returning real clinical data.

Plus the existing **VUL-0017** (which we keep as the "loop caught its own bad patch" narrative beat — Patch Agent generated fix, regression sweep replayed exploit 3/3, status flipped to `regressed`). VUL-0017 will be re-confirmed against the new pipeline before export.

## Report format

Each finding's `.md` file includes:

- **Title, severity, status, discovery date, campaign id, subcategory, mutation strategy** (front matter)
- **Judge verdict + confidence + model + rubric version**
- **Framework citations** — OWASP LLM Top 10 ID, MITRE ATLAS technique ID, HIPAA Security Rule safeguard reference, with `framework_versions` snapshot at finding-creation time
- **Clinical impact** — written for a non-security clinician audience
- **Reproduction steps** — exact attack input, expected response shape, observed response
- **Observed behavior** vs **Expected behavior**
- **Recommended remediation**

Templates and the citation-resolution helper live in [`apps/api/src/agents/documentation/template.py`](../../apps/api/src/agents/documentation/template.py).

## Pending links

Will be populated as findings are exported:

- `VUL-NNNN.md` — _post-sweep_
- `VUL-NNNN.md` — _post-sweep_
- `VUL-NNNN.md` — _post-sweep_
