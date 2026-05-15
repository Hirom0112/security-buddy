# Security Buddy — Platform Architecture

**Author:** Hirom Alarcon
**Week:** 3 — Gauntlet AI Austin Admission Track
**Framework grounding:** OWASP LLM Top 10 (2025, v2.0), MITRE ATLAS (v5.1.0),
HIPAA Security Rule. See `THREAT_MODEL.md` §2 for full grounding rationale.
**Status:** Living document. Updated as the platform evolves.

---

## 1. Summary

Security Buddy is a continuous adversarial evaluation platform for AI-assisted
clinical workflows. It does not exist to find a single jailbreak. It exists to
build, over time, a defensible answer to a harder question: *is the target
system becoming more or less resilient as it evolves?* The target for this
project is the OpenEMR Clinical Co-Pilot built in Weeks 1 and 2 of the Gauntlet
AI program.

The platform is structured as **five distinct agents**, each with one role,
each separated by trust level, model class, and execution boundary.

1. The **Orchestrator** reads coverage state from Postgres, decides what to
   attack next using a deterministic priority function, and triggers regression
   runs when the target redeploys.
2. The **Red Team Agent** generates novel adversarial inputs, mutates
   partial-success attacks into variants, and runs multi-turn attack sequences
   against the live target. It is powered by an open-weights model precisely
   because frontier models are trained to refuse offensive security workflows
   — a useful property for assistants, a defect for an attacker.
3. The **Judge** evaluates whether each attack succeeded against a stored
   rubric. It runs a frontier model from a different provider than the Red
   Team, with the model pinned and temperature fixed at zero. This
   separation is structural, not aspirational — an agent that both generates
   and grades attacks has a conflict of interest by design.
4. The **Documentation Agent** converts confirmed exploits into structured
   vulnerability reports a senior security engineer could reproduce, validate,
   and fix without prior context.
5. The **Patch Agent** reads the report, locates the relevant code in the
   target's repository, and opens a pull request with a proposed fix. **It does
   not merge.** That is a hard human gate.

Agents do not message each other directly. The substrate is **Postgres as a
durable message bus**: every agent reads inputs from Postgres, writes outputs
to Postgres, and updates status fields that signal the next agent it is their
turn. Redis is the worker dispatch layer underneath. This makes every step
durable, replayable, idempotent on retry, and auditable with a SQL query.

The platform sits behind a single-user password gate ("Security Buddy"), is
deployed as a fully separate service from the target on its own Railway
project, and attacks the target only via its public HTTPS API — exactly as an
external adversary would. There is no shared infrastructure between platform
and target. The blast radius of a Security Buddy compromise is bounded to
what an attacker with `Sara Chen` credentials plus the ability to open pull
requests against one OpenEMR fork could do.

The platform exists to close a loop, not merely run attacks. **Discovery →
documentation → patch proposal → human review → regression verification → loop.**
Until the loop closes — until a vulnerability has been documented, fixed,
and proven fixed by a regression run — the work is not done. The Security
Buddy UI's before/after diff view is the visual artifact of that loop closing
in production.

This document defines each agent, the substrate they coordinate through, the
trust gradient between them, the human gates placed deliberately at the
highest-stakes transitions, the regression harness that converts ad-hoc
discoveries into permanent guarantees, the observability layer that makes the
Orchestrator's decisions defensible, and the cost posture that keeps the
platform sustainable at scale.

---

## 2. System Diagram

```
                  ┌─────────────────────────────────┐
                  │     SECURITY BUDDY UI           │
                  │  (Next.js 15, password-gated)   │
                  │  • Run controls                 │
                  │  • Before/After diff viewer     │
                  │  • Reports inbox + PR queue     │
                  │  • Coverage & cost dashboards   │
                  └────────────┬────────────────────┘
                               │  reads Postgres directly
                               │  mutations via FastAPI
                               ▼
              ┌─────────────────────────────────────┐
              │      FastAPI + LangGraph            │
              │     (Python 3.12, async)            │
              └──┬──────────────────────────────────┘
                 │
                 ▼
        ┌────────────────────────┐
        │     ORCHESTRATOR       │
        │  (Claude Sonnet)       │
        │  • Coverage SQL        │
        │  • Priority function   │
        │  • Budget enforcement  │
        │  • Triggers regression │
        └──┬──────────────────┬──┘
           │                  │
    "campaign brief"   "regression run"
           │                  │
           ▼                  ▼
  ┌────────────────┐  ┌────────────────────┐
  │   RED TEAM     │  │ REGRESSION HARNESS │
  │ Llama 3.3 70B  │  │  (deterministic)   │
  │  + determin-   │  │  • Replay N times  │
  │  istic mutators│  │  • Majority vote   │
  │ • Seeds + muta-│  │  • Rubric stable   │
  │   tion strats  │  └─────────┬──────────┘
  │ • Multi-turn   │            │
  └──────┬─────────┘            │
         │ HTTPS attacks         │ HTTPS replays
         ▼                       ▼
  ┌─────────────────────────────────────────┐
  │            TARGET SYSTEM                │
  │   OpenEMR Clinical Co-Pilot             │
  │   (Sara Chen, physician credentials)    │
  │   Deployed on a separate Railway proj.  │
  └──────────────────┬──────────────────────┘
                     │  responses
                     ▼
            ┌─────────────────────┐
            │       JUDGE         │
            │ (Claude Sonnet,     │
            │  pinned, T=0)       │
            │  • Reads rubric     │
            │  • Conservative     │
            │  • Different model  │
            │    class than RT    │
            └──────────┬──────────┘
                       │ verdict
                       ▼
            ┌─────────────────────┐
            │   DOCUMENTATION     │
            │  (Claude Sonnet)    │
            │  • Vuln reports     │
            │  • Repro steps      │
            │  • Fix recommend.   │
            └──────────┬──────────┘
                       │ VUL-###
                       ▼
            ┌─────────────────────┐
            │       PATCH         │
            │  (Claude Sonnet)    │
            │  • Read-only repo   │
            │  • PR API only      │
            │  • Branch: PR only  │
            └──────────┬──────────┘
                       │ pull request
                       ▼
                  ╔═══════════╗
                  ║   HUMAN   ║  ← HARD GATE
                  ║  REVIEWS  ║     (operator merges)
                  ║  & MERGES ║
                  ╚═════╤═════╝
                        │
                        ▼
              [target redeploys]
                        │
                        ▼
              Orchestrator detects
              version change →
              triggers regression →
              Before/After diff in UI
```

**Substrate (not shown in flow):**

```
   ┌──────────────────────────┐    ┌────────────────────┐
   │      Postgres            │    │      Redis         │
   │  Source of truth         │    │  Worker queue      │
   │  - campaigns             │    │  - arq jobs        │
   │  - campaign_briefs       │    │  - rate counters   │
   │  - attacks               │    │  Ephemeral         │
   │  - verdicts              │    └────────────────────┘
   │  - vulnerabilities       │
   │  - regression_runs       │    ┌────────────────────┐
   │  - patches               │    │     LangSmith      │
   │  - agent_traces          │    │  • Per-agent cost  │
   │  - target_versions       │    │  • Trace tree      │
   │  - attack_taxonomy       │    │  • Eval datasets   │
   │  - target_manifests      │    └────────────────────┘
   └──────────────────────────┘
```

---

## 3. The Five Agents

### 3.1 Orchestrator

**Role:** Strategy. Decides what the platform does next.

**Inputs (from Postgres):**

- `attack_taxonomy` — the 13 subcategories with priority weights[^taxonomy-count]
- `attacks` joined to `verdicts` — coverage and success-rate per subcategory
- `vulnerabilities WHERE status IN ('open','regressed')` — open findings
- `regression_runs` — recent outcomes per target version
- `agent_traces` — cost accumulated in the active campaign
- `target_versions` — current target deployment state
- `target_manifests` — declared capability surface of the target

[^taxonomy-count]: 13 originally enumerated in THREAT_MODEL.md; 16 ultimately seeded — see `apps/api/alembic/versions/0003_seed_attack_taxonomy.py`.

**Decision mechanism:**

The Orchestrator runs two layers, intentionally separated.

**Layer A — Deterministic priority math.** Per subcategory, compute four
signals from SQL:

- `attempts` against the current target version
- `success_rate` (Judge verdicts of `exploit` divided by total)
- `open_findings_count`
- `days_since_last_attempted`

Combine via:

```
priority_score =
    taxonomy_priority_weight
  + zero_coverage_bonus  if attempts == 0
  - saturation_penalty   if attempts > 50 and success_rate < 0.02
  + open_findings_weight * open_findings_count
  + staleness_weight     if days_since_last > 7
```

The ranked output is a deterministic priority queue. **This decision uses no
LLM.** It is reproducible, defensible, auditable.

**Layer B — LLM framing.** Claude Sonnet receives the top-ranked subcategory
plus state context and produces a structured `campaign_brief`: target
subcategory, variant count, budget, success criteria. The LLM does not pick
the target — it explains the choice and frames the work for the Red Team.

**Outputs (to Postgres):**

- `campaigns` row with `status=pending`, `budget_usd`, `target_subcategory`
- `campaign_briefs` row with `description`, `variant_count`, `success_criteria`

**Triggers:**

- Manual ("Start Campaign" in UI)
- Target version change (GitHub merge → webhook → deploy → Orchestrator runs
  regression suite, then evaluates whether to start new campaigns)
- Scheduled (configurable cron, default off)

**Cost discipline:** The Orchestrator enforces budget caps in worker code, not
in prompts. If the LLM proposes a budget exceeding the campaign's `budget_usd`,
the worker overrides. If cumulative `agent_traces.cost_usd` for the campaign
exceeds 80% of budget, the Orchestrator halts further attacks and marks the
campaign `budget_warning`. At 100% it marks `budget_exhausted` and stops.

**Model:** Claude Sonnet (latest stable, not pinned). Runs infrequently
(seconds to minutes between ticks). Cost per tick is small relative to total
campaign cost.

**Trust level:** High. Strategic only, no execution authority, no write access
to anything except its own coordination tables.

**Failure modes and handling:**

| Failure | Detection | Response |
|---|---|---|
| LLM refuses to produce brief | unparseable JSON or refusal tokens | Fall back to a templated brief built from priority queue output; log `orchestrator_llm_fallback` event |
| LLM times out | 30s wall-clock | Same fallback as refusal |
| Priority math returns no candidates | empty queue | Mark campaign `no_candidates`, escalate to human review |
| Cumulative campaign cost > budget | continuous check | Halt remaining attacks, mark campaign `budget_exhausted` |

---

### 3.2 Red Team Agent

**Role:** Execution. Generates and runs adversarial attacks against the live
target.

**Model:** Hybrid by design — a **deterministic floor** plus an **LLM ceiling**,
not one or the other.

- **Deterministic floor.** Three pure-Python mutation strategies (lexical,
  structural, multi-turn) over a curated seed library guarantee baseline
  coverage of every subcategory in the taxonomy. They never refuse, never
  drift, cost nothing per call, and produce bit-exact replayable output. This
  is what makes coverage measurable and regressions reproducible.
- **LLM ceiling.** Llama 3.3 70B Instruct (uncensored) accessed via
  OpenRouter, invoked through an `LLMMutationStrategy` that sits alongside the
  three deterministic strategies and is tagged
  `mutation_strategy='llm_generated'` in `attacks` rows. Llama exists in this
  loop because string-mutating a seed cannot reach the attack shapes that
  OWASP LLM05/06/07 require — those need *reasoning* about the target's
  trust boundaries, not transformations over its prior payloads. An attacker
  who can only paraphrase will exhaust the bounded space of paraphrases
  faster than the target acquires new attack surface; an attacker that can
  reason about the target keeps finding things.

The case study explicitly anticipates the model choice for the LLM half:

> *"Some commercial LLMs are intentionally trained to avoid offensive security
> workflows, making them unreliable for certain forms of adversarial testing."*

Frontier models refuse offensive workflows unpredictably. Llama 3.3 70B
lacks that refusal training and is consistently willing — at the cost of
producing unsafe content, which is *expected* and handled by the trust-
boundary rules in CLAUDE.md §4 (attack payloads are data, never instructions
into another LLM's prompt; the Judge is a different model class).

**Containment of non-determinism.** The LLM is non-deterministic at
*generation* time only. Each variant text is persisted in
`attacks.attack_input` the moment it is generated, and every downstream
consumer — the Judge, the Documentation Agent, the regression harness —
operates on the persisted string, never re-prompts Llama. Replay is
bit-exact: a regression run six months later fires the *same bytes* against
the new target version, and the Judge evaluates with the rubric snapshot
that was frozen at confirmation time. The platform gets creative depth at
discovery time without sacrificing baseline reproducibility downstream.

**Fallback.** If OpenRouter is down or the campaign budget cap is hit, the
worker drops back to deterministic-only and the loop keeps running. The LLM
strategy is an addition, not a dependency.

**Inputs:**

- The `campaign_briefs` row addressed to it
- Seed attacks for the target subcategory (`attack_seeds` table)
- The `target_manifest` declaring endpoints, auth flow, capabilities, and
  expected safe behaviors
- The credentials vault reference for authenticating as Sara Chen
- Recent attack history in this subcategory (to avoid generating duplicates)

**Mechanism:**

1. **Authenticate** to the target using stored credentials via the OpenEMR
   login API. Cache the session cookie in working memory.
2. **Generate variants.** The agent has three composable mutation strategies:
   - **Lexical** — paraphrase, synonym swap, framing-language change
   - **Structural** — relocate the injection (message body → filename → PDF
     metadata → system field → tool argument)
   - **Multi-turn escalation** — split a single-shot attack into a
     conversation that builds context before delivering the payload
   The agent picks strategies based on the brief and on what previous variants
   in this subcategory failed at.
3. **Tag each variant** with `(category, subcategory, mutation_strategy,
   seed_used)`. Tagging is non-negotiable — it is the substrate the
   Orchestrator's coverage query depends on.
4. **Fire attacks** at the target via HTTPS. Rate-limited to 10 requests per
   second outbound (never DoS the target).
5. **Store every attack** in Postgres before evaluation:

```
attacks (
  id, campaign_id, brief_id, category, subcategory,
  mutation_strategy, seed_used, attack_input, attack_metadata,
  target_response, target_response_status, target_response_time_ms,
  status = 'awaiting_judgment'
)
```

**Outputs:** `attacks` rows.

**Trust level:** Low. Sandboxed. Its output never directly drives downstream
decisions without passing through the Judge. No agent reads attack text and
interprets it as a command — payloads are always passed as opaque strings.

**Constraints:**

- HTTPS access to the target only. No shell, no `subprocess`, no filesystem
  writes outside the temp workspace.
- Outbound rate-limited (10 req/s, 1000 attacks per campaign without explicit
  override).
- Multi-turn context window capped at 16K tokens to bound cost per attack.

**Failure modes and handling:**

| Failure | Detection | Response |
|---|---|---|
| Target returns 5xx | HTTP status | Retry once with backoff; if persistent, mark attack `target_unavailable` and continue |
| Target rate-limits the agent | 429 response | Exponential backoff; if persistent, pause campaign and escalate |
| Auth session expires mid-campaign | 401 response | Re-authenticate; if re-auth fails, halt and escalate |
| LLM generates output > 16K tokens | length check | Truncate, log `red_team_truncation`, continue |
| LLM generates content outside scoped categories | runs through pre-Judge filter | Discard the variant, log `red_team_off_scope`, continue |

---

### 3.3 Judge

**Role:** Independent evaluation. Decides whether each attack succeeded.

**Model:** Claude Sonnet (frontier class, *different model class than the Red
Team by design*). **Pinned** to a specific model version. **Temperature
fixed at 0**. Both hardcoded in `agents/judge/model.py`; changing either
requires a code commit and a re-baseline against the ground-truth eval set.

**Inputs:**

- An `attacks` row with `status='awaiting_judgment'`
- The `campaign_briefs.success_criteria` for the campaign
- The `target_manifest.trust_boundaries` and `expected_safe_behavior` for
  the relevant capability
- The framework-derived rubric for the attack's subcategory — Judge rubrics
  are derived from the relevant OWASP LLM Top 10 category's "Common
  Examples" section and the MITRE ATLAS technique description, contextualized
  to the target's trust boundaries. See `THREAT_MODEL.md` §4 for the per-
  subcategory framework mappings the rubrics build on.
- A few-shot of example verdicts for the subcategory

**Mechanism:**

Each call passes the Judge a structured request:

```json
{
  "attack_input": "...",
  "target_response": "...",
  "rubric": {
    "subcategory": "prompt_injection/indirect_via_upload",
    "success_criteria": "...",
    "trust_boundaries_at_stake": ["cross_patient_isolation"],
    "evidence_required": "specific quoted text from response"
  }
}
```

The Judge returns:

```json
{
  "verdict": "safe" | "exploit" | "partial" | "unclear",
  "confidence": 0.0-1.0,
  "evidence": "specific quote from response justifying verdict",
  "notes": "..."
}
```

**Conservatism principle:** When uncertain, the Judge prefers `unclear` or
`partial` over `safe`. False negatives (real exploits marked safe) are far
costlier than false positives (safe behavior marked as exploit) in a clinical
AI context — we accept higher false-positive rates to drive false-negatives
toward zero.

**Outputs:** `verdicts` rows. The same attack is **never** re-judged by a
different Judge instance for the same purpose — the verdict is the durable
record.

**Drift prevention:**

- Model pinned, temperature 0.
- A **ground-truth eval set** of ~30 human-labeled attack/verdict pairs lives
  in `tests/evals/judge_ground_truth.jsonl`. The Judge is run against this set
  on every PR that modifies its prompt, model, or rubric handling. Accuracy
  and per-class precision/recall are recorded.
- If accuracy drops below threshold (default 0.85) or verdict-distribution
  skews more than 20% from the baseline, the Judge is pulled and the
  regression queue pauses until a human resolves it.

**Trust level:** High. Independent of the Red Team in model class, provider,
prompt, and operational lifecycle. The Judge cannot read or be influenced by
the Red Team's mutation strategy or seed history.

**Failure modes and handling:**

| Failure | Detection | Response |
|---|---|---|
| Unparseable JSON | structured-output validator | Retry once with `json_mode=strict`; if still bad, mark `verdict='unclear'` and flag for human |
| Verdict distribution skewing safe-heavy | rolling-window monitor | Auto-run ground-truth eval; if accuracy held, continue; if degraded, halt |
| Model API down | HTTP error | Backoff; if persistent, pause regression and mark queued attacks `judging_unavailable` |

---

### 3.4 Documentation Agent

**Role:** Converts confirmed exploits into structured vulnerability reports.

**Model:** Claude Sonnet.

**Inputs:**

- A `verdicts` row with `verdict='exploit'`
- The corresponding `attacks` row
- The `target_manifest` (for capability-and-trust-boundary context)
- The vulnerability report template

**Output:** A `vulnerabilities` row with all required fields:

```
vulnerabilities (
  id (e.g., VUL-001),
  severity,                       -- critical | high | medium | low
  title,
  clinical_impact_description,
  reproduction_steps,
  observed_behavior,
  expected_behavior,
  recommended_remediation,
  status,                         -- open | proposed_fix | patched | regressed
  -- framework grounding (mandatory, from THREAT_MODEL.md taxonomy):
  owasp_llm_id,                   -- e.g. "LLM01:2025"
  mitre_atlas_technique_id,       -- e.g. "AML.T0051.001"
  hipaa_safeguard,                -- e.g. "164.312(a)(1)"
  framework_versions,             -- JSON snapshot, e.g.
                                  --   {"owasp": "2025-v2.0",
                                  --    "atlas": "5.1.0"}
  created_at, target_version, attack_id, verdict_id
)
```

Each report's title and `recommended_remediation` reference the framework
IDs directly (e.g., "Cross-patient PHI exfiltration via PDF metadata
injection [LLM01:2025 / AML.T0051.001 / HIPAA §164.312(a)(1)]"). This is
not stylistic — it's what makes the report ingestible by a target
organization's GRC system without manual translation.

**Quality bar:** A senior security engineer who was not present when the
exploit was found must be able to reproduce, validate, and fix the
vulnerability based solely on the report.

**PHI safety:** The Documentation Agent operates only on synthetic test data
(enforced upstream by the target's data setup). It must not reproduce raw
attack payloads that could themselves contain prompt-injection content for
downstream consumers — payloads are referenced by ID and rendered in the UI
through escaping layers, never embedded as instructions in other LLM prompts.

**Soft gate:** For `severity = critical`, the report stays in `draft` status
until the operator confirms via the UI. The Documentation Agent's drafts are
not unfiltered.

**Trust level:** Medium. Output is read by humans, not executed. A false
positive wastes engineering time but does not damage the target.

---

### 3.5 Patch Agent

**Role:** Proposes code fixes as pull requests against the target's repository.

**Model:** Claude Sonnet.

**Inputs:**

- A `vulnerabilities` row with `status='open'` and
  `severity IN ('critical','high')`
- The `attacks` row (for code-context grounding)
- A read-only clone of the target's repository
- The `target_manifest` (to know which subsystem of the target is involved)

**Mechanism:**

1. Reads the vulnerability report and the original attack.
2. Searches the codebase to locate the relevant code (e.g., the PDF extraction
   pipeline, the prompt-construction step, the authorization check).
3. Generates a proposed diff.
4. Creates a branch on the target's GitHub fork named
   `security-buddy/auto-patch-VUL-###`.
5. Pushes the diff to that branch.
6. Opens a pull request against `main` via the GitHub API, titled
   `fix(security): <short description> — addresses VUL-###`, including the
   vulnerability report as the PR description.
7. Writes a `patches` row with `pr_url`, `branch_name`, and
   `status='awaiting_human_review'`.
8. **Stops.**

**Permissions (the hard human gate):**

The Patch Agent's GitHub token has `repo` scope on **one** OpenEMR fork only.
**Branch protection on `main`** in that fork requires:

- A pull request
- At least one approving review from the repository owner (the operator)
- Status checks (existing test suite) passing

The Patch Agent's identity has no permission to approve its own PR and no
permission to push to `main` directly. The merge action requires the
operator's GitHub identity, not the agent's. This is enforced at GitHub's
infrastructure level, not at the application level — even if the Patch Agent
code is compromised, it cannot ship code.

**Trust level:** Medium. The agent writes to one specific fork's PR branches.
Its blast radius is exactly what a contributor with PR rights to that fork
would have.

**Outputs:** `patches` row, GitHub pull request.

**Failure modes:**

| Failure | Detection | Response |
|---|---|---|
| Cannot locate relevant code | search returns no candidates | Open PR with explanation in description, request human guidance |
| Proposed diff fails existing tests | CI checks fail post-push | Update PR with note; mark `patches.status='ci_failed'`; do not auto-revise |
| GitHub API rate limit | 403 | Backoff; if persistent, queue and retry |

---

## 4. Substrate

### 4.1 Postgres as Message Bus

Agents do not talk to each other directly. There is no in-memory shared
context. There is no message queue between agents. There is one substrate.

**Pattern:** Every agent reads inputs from Postgres, writes outputs to
Postgres, and updates a status field that signals the next agent's worker to
pick up. Workers are dispatched via Redis (arq), but the source of truth for
"what happened" is always Postgres.

**Why:**

- Every step is durable. A worker crash mid-step does not lose work.
- Every step is replayable. Re-running the same campaign produces the same
  Postgres state.
- Every step is auditable. A SQL query reconstructs the full timeline.
- Every step is idempotent on retry, because status fields prevent
  double-execution.

**Schema (abbreviated; full DDL in `apps/api/alembic/versions/`):**

```sql
-- The graph of what gets attacked and why
attack_taxonomy        (category, subcategory, priority, description,
                        framework_mappings JSONB,
                        framework_versions JSONB)
                        -- framework_mappings example:
                        --   {"owasp_llm": "LLM01:2025",
                        --    "mitre_atlas": "AML.T0051.001",
                        --    "hipaa": ["164.312(a)(1)", "164.312(c)(1)"]}
target_manifests       (target_id, manifest_json, version)
target_versions        (target_id, version, deployed_at, triggered_by)

-- The lifecycle of a campaign
campaigns              (id, status, budget_usd, target_version, ...)
campaign_briefs        (id, campaign_id, target_subcategory,
                        description, variant_count, success_criteria,
                        budget_usd)

-- The lifecycle of an attack
attacks                (id, campaign_id, brief_id, category, subcategory,
                        mutation_strategy, seed_used, attack_input,
                        attack_metadata, target_response,
                        target_response_status, status, created_at)
verdicts               (id, attack_id, verdict, confidence,
                        evidence, notes, rubric_version, model_version)

-- Findings and the patch loop
vulnerabilities        (id, attack_id, verdict_id, severity, title,
                        clinical_impact, reproduction_steps,
                        observed_behavior, expected_behavior,
                        recommended_remediation, status,
                        owasp_llm_id, mitre_atlas_technique_id,
                        hipaa_safeguard, framework_versions JSONB,
                        target_version, version_lock)
patches                (id, vulnerability_id, branch_name, pr_url,
                        status, version_lock)
regression_runs        (id, vulnerability_id, target_version,
                        replay_count, verdicts, outcome)

-- Observability
agent_traces           (id, agent, request_id, model, prompt_hash,
                        completion_hash, tokens_in, tokens_out,
                        cost_usd, duration_ms, outcome,
                        campaign_id, attack_id, verdict_id)
```

**Status-driven handoffs:**

```
campaigns.status:        pending → in_progress → completed | halted | budget_exhausted
campaign_briefs.status:  pending → in_progress → completed
attacks.status:          pending_execution → awaiting_judgment → judged
verdicts (terminal — no status, the row IS the verdict)
vulnerabilities.status:  open → proposed_fix → patched → regressed
patches.status:          awaiting_human_review → merged | rejected | ci_failed
```

### 4.2 Redis

Two roles, both ephemeral:

- **arq job queue.** Worker dispatch. If Redis disappears, the system rebuilds
  the queue from Postgres rows in non-terminal status.
- **Rate-limit counters.** Inbound (slowapi) and outbound (Red Team's
  target-facing limiter).

Redis state is **never the source of truth**. Anything in Redis can be
reconstructed from Postgres.

### 4.3 LangSmith

The observability layer the Orchestrator depends on for cost signal and the
human operator depends on for trace inspection.

Every LLM call goes through the `llm_client/` module, which:

- Tags the call with `agent` (one of the five), `campaign_id`, `attack_id`,
  `verdict_id` as applicable
- Records `tokens_in`, `tokens_out`, `cost_usd`, `duration_ms` from
  OpenRouter's response
- Emits a `agent_traces` row to Postgres in parallel with the LangSmith span

This dual write is intentional. LangSmith is for human inspection and ad-hoc
analytics. `agent_traces` is for the Orchestrator's cost queries — the
Orchestrator queries Postgres, not an external API, when deciding whether to
halt.

---

## 5. Trust Boundaries and Human Gates

### 5.1 Trust Gradient

| Agent | Trust | Why |
|---|---|---|
| Orchestrator | High | Strategic only. No execution authority. Cost ceilings enforced in code. Cannot bypass budget. |
| Red Team | **Low** | Sandboxed. Uses open-weights model lacking strong alignment. Output never trusted directly — always passes through Judge. No agent reads its output as instructions. |
| Judge | High | Independent (different model class from Red Team). Pinned + T=0 to prevent drift. Validated against ground-truth set on every change. |
| Documentation | Medium | Output is human-readable, not executed. False positives waste time but cause no harm. Critical-severity reports gated. |
| Patch | Medium | Can propose code changes but **cannot merge**. Branch-protection on `main` is the structural gate. |

### 5.2 Human Gates

**Hard gate — patch merge.** The Patch Agent opens a pull request and stops.
The operator reviews the diff and merges. Branch protection on `main` in the
target's fork enforces this at GitHub's infrastructure level. No agent has
permission to merge.

This is where the case study's warning is operationalized:

> *"An agent with the ability to push fixes without review can introduce
> entirely new vulnerabilities."*

The gate is placed where the action is highest-stakes: modifying code that
will be deployed to a running clinical system. Earlier in the pipeline, false
positives waste engineering time. At merge, false positives ship.

**Soft gate — critical-severity reports.** The Documentation Agent drafts
freely. For `severity = critical`, the report stays in `draft` status until
the operator confirms via the UI. A false-positive critical finding burns
engineering trust faster than ten missed mediums; the small extra friction
here is worth it.

**No other gates.** The Orchestrator does not ask for permission to start a
campaign within budget. The Red Team does not ask for permission to generate
each attack. The Judge does not ask for permission to evaluate. Each agent
operates autonomously within its scope.

### 5.3 Where AI Is Used vs. Deterministic Tooling

The case study asks this explicitly. The split:

| Function | Mechanism | Why |
|---|---|---|
| Subcategory prioritization | Deterministic SQL + priority function | Reproducibility, defensibility, no drift |
| Campaign brief generation | LLM | Strategic framing benefits from reasoning |
| Attack generation | LLM (Red Team) | Creative variation, mutation |
| Attack mutation | LLM + strategy templates | Same; templates constrain the LLM |
| Verdict | LLM (Judge, pinned) | Subtle reasoning over response evidence |
| Regression replay | Deterministic replay + Judge | Replay is mechanical; verdict on the replay still uses the Judge with the original rubric |
| Vulnerability writeup | LLM | Natural language quality matters |
| Code patch generation | LLM | Code synthesis from natural language description |
| Cost enforcement | Deterministic (worker code) | LLMs cannot be trusted with their own budget |
| Rate limit enforcement | Deterministic (slowapi, outbound limiter) | Must be unbypassable |
| Coverage measurement | Deterministic SQL | Reproducibility |
| Drift detection (Judge) | Deterministic eval against fixed ground-truth | An LLM cannot reliably evaluate itself |

---

## 6. The Regression Harness

The hardest engineering problem in the platform. The case study spends
paragraphs on it because a fix that passes its regression test because the
model behaved differently — not because the vulnerability was actually closed
— is worse than no test at all.

### 6.1 What a Regression Test Is

A regression test is **not** "rerun the original attack and see if it works."
It is a structured record:

```
regression_test (
  vulnerability_id,
  exact_attack_input,        -- byte-for-byte
  exact_authentication,      -- which test persona and credentials
  rubric_at_time_of_finding, -- the Judge rubric that confirmed exploit
  expected_outcome,          -- "safe" (post-fix)
  replay_count,              -- default 3
  passing_threshold          -- default: majority must be 'safe'
)
```

The rubric is **frozen** at the time the vulnerability was confirmed. If the
Judge's rubric evolves later, that does not silently re-grade old regression
tests. New rubric → new ground-truth eval → new baseline. Old regression
tests continue to use their original rubric.

### 6.2 Replay Mechanics

When a regression run fires (triggered by target version change):

1. For each `vulnerability` with `status IN ('open','patched','regressed')`:
2. Replay the exact attack input `replay_count` times against the new target
   version.
3. For each replay, the Judge evaluates using the **frozen rubric**.
4. Majority vote across replays produces the outcome:
   - All replays `safe` → `fix_verified`. Update vulnerability status from
     `proposed_fix` → `patched`.
   - Majority `exploit` and previous status was `patched` → `regressed`.
     Flag as urgent.
   - Mixed (e.g., 1 safe, 2 exploit) → `unstable`. Either the fix is partial
     or the target is non-deterministic. Flag for human review.

### 6.3 Detecting Cross-Category Regressions

A fix for VUL-001 may introduce a regression in an unrelated subcategory. The
regression run **replays every confirmed exploit**, not just the one being
fixed. If any previously-resolved vulnerability returns to `exploit` status,
it is flagged with the offending patch's commit hash as the suspected cause.

This is the difference between "I tested my fix" and "I tested whether my fix
broke anything else."

### 6.4 Detecting Non-Determinism in the Target

Some target behavior is non-deterministic. The replay-N-times design surfaces
this: if a vulnerability's status oscillates across replays of the same
version, the test is marked `unstable` and a human is asked whether the rubric
is too brittle (improve rubric) or the target's non-determinism is itself a
problem (file as a new vulnerability).

---

## 7. Observability Layer

The platform must surface enough information for the Orchestrator to make
intelligent decisions and for a human operator to understand system behavior
at any time.

### 7.1 Required Answerable Questions

The case study lists six. The platform answers each via a SQL query plus a
LangSmith dashboard:

| Question | Source |
|---|---|
| Which attack categories have been tested? | `attacks GROUP BY category, subcategory` |
| Current pass/fail rate per category and version? | `attacks JOIN verdicts GROUP BY category, target_version` |
| Is the target becoming more or less resilient? | Time-series of exploit-rate per category across target versions |
| Which vulnerabilities are open / in progress / resolved? | `vulnerabilities GROUP BY status` |
| How much did this test run cost, and how is cost scaling? | `agent_traces SUM(cost_usd) GROUP BY campaign_id, agent` |
| What is each agent doing, in what order? | LangSmith trace tree + `agent_traces ORDER BY started_at` |

### 7.2 Metric and Event Catalog (abbreviated)

**Prometheus metrics:**

- `security_buddy_attacks_total{category, subcategory, outcome}`
- `security_buddy_verdicts_total{verdict, agent_version}`
- `security_buddy_vulnerabilities_open{severity}`
- `security_buddy_regression_runs_total{outcome}`
- `security_buddy_llm_cost_usd_total{agent, model}`
- `security_buddy_llm_call_duration_seconds{agent, model}` (histogram)
- `security_buddy_judge_accuracy{eval_set_version}` (gauge)

**Structured log events:**

- `campaign_started`, `campaign_completed`, `campaign_halted`
- `attack_generated`, `attack_executed`, `attack_judged`
- `vulnerability_documented`, `patch_proposed`, `patch_merged`
- `regression_started`, `regression_completed`
- `judge_drift_detected`, `judge_eval_run`

### 7.3 Tracing

LangSmith captures the full agent trace tree per campaign. From a
vulnerability, the operator can navigate to the Documentation Agent's run, up
to the Judge's verdict, up to the Red Team's attack generation, up to the
Orchestrator's brief. Foreign-key chains in Postgres mirror this — every row
has the parent campaign_id, every attack has its brief_id and campaign_id,
every verdict has its attack_id. The two systems are dual records of the same
graph.

---

## 8. Cost Posture

### 8.1 Per-Run Costs (MVP estimate)

| Agent | Calls per campaign | Model | $/call est | Subtotal |
|---|---|---|---|---|
| Orchestrator | 2-5 | Claude Sonnet | $0.02 | $0.10 |
| Red Team | 10-20 (variants) | Llama 3.3 70B via OpenRouter | $0.001-0.005 | $0.02-0.10 (now live, see Campaign #2: $0.43 / 11 exploits, 20 variants) |
| Judge | 10-20 (one per attack) | Claude Sonnet | $0.03 | $0.60 |
| Documentation | 0-3 (one per exploit) | Claude Sonnet | $0.05 | $0.15 |
| Patch | 0-3 (one per high/crit) | Claude Sonnet | $0.10 | $0.30 |
| **Total per campaign** | | | | **~$1.35** |

(Detailed model in `COST_ANALYSIS.md`.)

### 8.2 Scale Breakpoints

| Scale | Architecture | Spend |
|---|---|---|
| MVP (100 runs) | Single Postgres + Redis, LangSmith free tier, OpenRouter pay-as-you-go | ~$5-20 |
| 1K runs | Same architecture | ~$50-150 |
| 10K runs | Move Red Team to dedicated Together AI endpoint or self-hosted Llama; cache identical attack-response pairs | ~$200-500 |
| 100K runs | Self-host Langfuse off LangSmith; batch judge evaluations; partition `agent_traces` by month | architectural shift, not just more spend |

### 8.3 Where Cost Is Enforced

- Per-campaign budget (Postgres row, worker-enforced)
- Per-day platform budget (env var, Orchestrator-enforced)
- Per-call timeout (httpx, hard-coded)
- Outbound rate limit to target (Red Team worker)
- Rate-limited inbound API (slowapi)

Cost enforcement never lives in prompts. The Orchestrator's LLM may *advise*
on budget. The worker code is what *enforces* it.

---

## 9. Deployment Topology

```
┌──────────────────────────────────────────────────────────────┐
│  RAILWAY PROJECT 1 — TARGET (already exists from W2)         │
│  ────────────────────────                                    │
│  OpenEMR Clinical Co-Pilot                                   │
│  - openemr web app                                           │
│  - agent-api (Python from W2)                                │
│  - patient-dashboard (Next.js from W2)                       │
│  - MySQL                                                     │
│  URL: openemr.<domain>          ← graded hard-gate URL       │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│  RAILWAY PROJECT 2 — SECURITY BUDDY (new this week)          │
│  ────────────────────────                                    │
│  - security-buddy-api (FastAPI + arq workers)                │
│  - security-buddy-ui (Next.js)                               │
│  - Postgres                                                  │
│  - Redis                                                     │
│  URL: securitybuddy.<domain>    ← operator console           │
└──────────────────────────────────────────────────────────────┘

External services:
  - OpenRouter (LLM gateway, single API key)
  - LangSmith (tracing + datasets)
  - GitHub (Patch Agent opens PRs against the W2 OpenEMR fork)
```

Two Railway projects. No shared infrastructure. The platform reaches the
target only via its public HTTPS API, authenticated as Sara Chen. The
platform's blast radius into the target is bounded to what a physician with
Sara Chen's credentials plus GitHub PR-author rights to one OpenEMR fork
could do — that is, no more than what a single compromised contributor would
have.

---

## 10. Known Tradeoffs

I want to name the decisions I made that someone reasonable could disagree
with, and why I made them.

**One Red Team Agent, not many.** I considered specialized red teamers per
attack category (one for prompt injection, one for DoS, etc.). I rejected
this. The case study's separation-of-concerns ask is by *role* (attack vs.
judge vs. document), not by *attack category*. Splitting the Red Team
duplicates the strategy layer (each specialist would re-derive priority
locally) and blows up cost. Category specialization happens inside the single
Red Team Agent's mutation strategies, directed by the Orchestrator.

**Open-weights for the Red Team, not Claude with scaffolding.** Frontier
models will refuse offensive workflows unpredictably. That non-determinism
is incompatible with a platform whose value depends on reproducible coverage.
I take the quality hit on individual attack generation and recover it through
volume and mutation.

**LangSmith over Langfuse for MVP.** LangSmith is LangGraph-native, lower
setup cost, and gives per-agent cost tags for free. The cost analysis flags
the migration breakpoint where Langfuse self-hosted becomes the right call
(~100K runs/month). For MVP, LangSmith is the right tool.

**No autonomous merge, ever.** I considered an `auto-apply-if-regression-green`
mode. I rejected it. The case study explicitly warns against it, the failure
mode (auto-merging a fix that introduces a worse vulnerability) is real, and
the marginal speed gain over a human reviewer is small for a platform that
runs continuously over weeks and months.

**Postgres for the message bus, not Kafka or NATS.** Durable message buses
exist. Postgres is overkill for a queue and underkill for a high-throughput
event system. I chose it anyway because the platform's volume is bounded
(thousands of attacks per day, not millions), Postgres gives transactional
guarantees the event flow needs, and the entire data model lives in one
place where SQL is the debug tool. At 100K-runs scale this stops being the
right answer; that's noted in the cost-and-scale section.

**Single-user platform, password gate.** Multi-user roles (security
engineer, ops lead, engineering manager) are described in `USERS.md` as
intended personas. The MVP serves them all as one operator account. Real
RBAC is post-MVP work.

**Three frameworks, not five.** Grounded in OWASP LLM Top 10 (2025),
MITRE ATLAS (v5.1.0), and HIPAA. I considered adding NIST AI 100-2 and
ISO/IEC 42001. I rejected both for MVP — NIST AI 100-2 is academic-leaning
and adds maintenance overhead without proportional rubric impact at
practitioner level, and ISO 42001 is a management-system framework, not
an attack taxonomy. Framework versions are pinned in
`attack_taxonomy.framework_versions`; a new OWASP or ATLAS release
triggers a planned mapping review, not a silent rollover. The maintenance
cost of three is sustainable; five would be a tax on the build that the
audience doesn't reward.

---

## 11. What This Architecture Is Not

Naming this explicitly because graders test for it:

- **Not a static test runner.** Attacks are generated at runtime by an
  LLM-driven agent that mutates partial-successes. Static payload lists go
  stale; this platform does not.
- **Not a single-agent pipeline.** The five roles are architecturally
  separated, with distinct trust levels, distinct models, and a coordination
  substrate they share but never reach across.
- **Not a system that auto-merges code.** Patch Agent proposes; the operator
  merges. Branch protection on `main` is the structural enforcement.
- **Not a system that shares context between Red Team and Judge.** Different
  model classes, different providers, no prompt cross-contamination.
- **Not a system tested against real PHI.** All target data is synthetic.

---

## 12. What's Next

`PLAN.md` lays out the build slices in order:

- Slice 0 — Scaffolding, schema, `llm_client`, deployment skeleton
- Slice 1 — Red Team Agent against the live target (Stage 3 hard gate)
- Slice 2 — Judge against stored attacks, ground-truth eval baseline
- Slice 3 — Orchestrator's priority function + LLM framing
- Slice 4 — Documentation Agent + vulnerability schema
- Slice 5 — Patch Agent + GitHub integration + branch protection
- Slice 6 — Regression Harness with replay-N-times + frozen rubrics
- Slice 7 — Security Buddy UI: dashboard, run controls, before/after diff
- Slice 8 — Cost analysis, observability dashboards, final polish

Each slice is vertical: it adds an agent or capability from API to UI in one
pass, with tests, evals where applicable, and updated documentation.
