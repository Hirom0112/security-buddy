# EVAL_BASELINES.md

Recorded baselines for every LLM-driven component. Read **before** opening
any PR that changes a prompt, model, rubric, or eval set — and append a
new entry to the corresponding table when those things change.

CLAUDE.md §6 mandates that Judge changes carry an eval baseline diff. This
file is where that diff lives.

---

## Judge — verdict adjudication

**Ground-truth set:** `apps/api/tests/evals/judge_ground_truth.jsonl`
**Runner:** `apps/api/tests/evals/run_judge_eval.py`
**Threshold:** 0.85 accuracy (eval runner exits non-zero below this).

### Ground-truth composition (v1)

- 32 hand-authored (attack_input, target_response) pairs.
- Balanced 8 per CRITICAL subcategory: `prompt_injection/indirect_via_upload`,
  `data_exfiltration/cross_patient_leakage`,
  `tool_misuse/unintended_invocation`, `identity_role/privilege_escalation`.
- Verdict distribution: 17 safe / 9 exploit / 4 partial / 2 unclear.
- Includes adversarial edges: nested canary leak inside otherwise-safe response,
  partial-disclosure cases, empty target responses (unclear).

All identifiers are synthetic (`pt-NNN` namespace per `docs/TARGET_MANIFEST.md`
§7). No real PHI.

### Baseline history

| git sha | date       | model                          | accuracy | safe P/R | exploit P/R | partial P/R | unclear P/R | cost (USD) | notes |
|---------|------------|--------------------------------|----------|----------|-------------|-------------|-------------|------------|-------|
| _pending_ | 2026-05-12 | anthropic/claude-sonnet-4.6 | _not yet recorded_ | – | – | – | – | – | Awaiting first eval run after Slice 2 merge. Runner ready; operator to execute with valid OPENROUTER_API_KEY. |

When the first eval runs, replace the `_pending_` row with the result and keep
appending rows on every prompt/model/rubric change. Both the old and new
accuracy must appear in the PR that introduces the change.
