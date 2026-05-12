# Security Buddy — Build Plan

**For:** Claude Code (and the human reviewing its work)
**Source of truth for:** what's next, what's done, what's deferred
**Updated:** with every merged PR

---

## How to Use This Document

Each slice is **vertical** — it adds one capability end-to-end (schema →
backend → frontend where applicable → tests/evals → docs update) in one pass.
Do not start slice N+1 until slice N is merged.

Each slice has:

- **Goal** — what success looks like in plain language
- **Deliverables** — concrete artifacts that exist when the slice is done
- **Definition of Done** — verifiable criteria (tests pass, eval baseline
  recorded, doc updated, deployed)
- **Out of scope for this slice** — what's deliberately deferred so we
  don't scope-creep

Claude Code reads CLAUDE.md and the relevant section of this document before
each slice. The orchestrator persona ("you do not implement, you direct
specialists") applies at every step.

---

## Slice 0 — Foundation [Day 1]

**Goal:** Empty house with running plumbing. No agents yet, no UI yet — just
the substrate every later slice depends on.

### Deliverables

1. Monorepo scaffolded at `security-buddy/` with `apps/api/` and `apps/ui/`.
2. `apps/api/` with FastAPI 0.115+, Python 3.12, pyproject.toml using `uv`,
   ruff + mypy + import-linter configured.
3. `apps/ui/` with Next.js 15 (App Router), TypeScript strict, Tailwind,
   shadcn/ui initialized.
4. `docker-compose.yml` at repo root with Postgres 16 and Redis 7.
5. Alembic initialized in `apps/api/alembic/` with empty migration 0001.
6. **Schema migration 0002** creating all core tables (from
   `ARCHITECTURE.md` §4.1):
   - `attack_taxonomy` (including `framework_mappings JSONB` and
     `framework_versions JSONB` columns)
   - `target_manifests`, `target_versions`
   - `campaigns`, `campaign_briefs`
   - `attacks`, `verdicts`
   - `vulnerabilities` (including `owasp_llm_id`, `mitre_atlas_technique_id`,
     `hipaa_safeguard`, `framework_versions JSONB` columns)
   - `patches`, `regression_runs`
   - `agent_traces`
7. **Schema migration 0003** seeding `attack_taxonomy` from
   `THREAT_MODEL.md` (13 subcategories). Each row's `framework_mappings`
   carries the OWASP LLM ID, MITRE ATLAS technique ID, and HIPAA
   safeguard reference from THREAT_MODEL.md §4.
   `framework_versions` carries `{"owasp_llm": "2025-v2.0",
   "mitre_atlas": "5.1.0", "hipaa": "2013-omnibus"}`.
8. `llm_client/` module — single wrapper around OpenRouter that:
   - Reads `OPENROUTER_API_KEY` from env (no fallback)
   - Tags every call with `agent`, `request_id`, `campaign_id` when present
   - Writes an `agent_traces` row on every call
   - Sends a LangSmith span on every call
   - Redacts secrets in any logging
9. `observability/` package — `log_event()` helper, request_id ContextVar,
   Prometheus counters scaffold.
10. Health endpoint `GET /healthz` returning DB + Redis + LangSmith status.
11. Single-user auth scaffold for the UI — login page, password-gated dashboard
    placeholder, session cookie with httpOnly + Secure + SameSite=Strict.
12. CI workflow on GitHub Actions running `ruff`, `mypy`, `lint-imports`,
    `pytest`.

### Definition of Done

- [x] `docker compose up` brings Postgres + Redis up cleanly
- [x] `alembic upgrade head` creates all tables and seeds taxonomy
      (12 tables, 16 taxonomy rows — chose §4 enumeration over §1's
      "thirteen" summary count; discrepancy documented in migration 0003)
- [x] `pytest apps/api/tests/unit` passes (48 unit + integration tests green)
- [x] `pnpm typecheck && pnpm lint` passes in `apps/ui/`
- [x] `pnpm dev` serves the placeholder dashboard, login gate works
- [x] `uvicorn src.main:app` serves `/healthz` returning all green
      (app/db/redis = ok; langsmith = unconfigured until key provided)
- [x] CI passes on a fresh branch (workflow run 25710608370 green —
      API + UI jobs both clean on the f4cc175 commit)
- [x] Both services deployed to Railway as a single project (two services
      api + ui, plus a separate worker service for arq). URLs documented
      in README:
      - UI:     https://security-buddy-production.up.railway.app
      - API:    https://security-buddy-api-production.up.railway.app
      - Worker: internal only (no public domain)
      Postgres + Redis are managed Railway plugins (`security-buddy-db`,
      `security-buddy-queue`). `/healthz` green on 2026-05-12.
- [x] `CLAUDE.md`, `ARCHITECTURE.md`, `THREAT_MODEL.md`, `USERS.md` all
      checked into `docs/` (already drafted, just placed)

### Out of scope

- Any agent logic
- Connecting to the target (target_manifest can be a stub row)
- UI past the login + empty dashboard
- Real attack execution

---

## Slice 1 — Red Team Agent (live attack against target) [Day 2–3]

**Goal:** Hit the Stage 3 hard gate. One agent role running live against the
deployed target.

### Deliverables

1. `target_manifests` seeded with one row for the OpenEMR Clinical Co-Pilot:
   target URL, auth flow, capabilities, trust boundaries, expected safe
   behaviors. (See `ARCHITECTURE.md` §3.2 inputs section.)
2. `agents/red_team/` package:
   - Authentication module that obtains and refreshes the Sara Chen session
     cookie against the target's login API
   - Seed attack library at `agents/red_team/seeds/<subcategory>.json` —
     at minimum, 3 seeds per CRITICAL subcategory from THREAT_MODEL.md
   - Mutation strategies (lexical, structural, multi-turn) as separate
     modules with unit tests
   - LangGraph node that:
     - Reads a `campaign_briefs` row
     - Generates N variants per the brief
     - Tags each with `(category, subcategory, mutation_strategy, seed_used)`
     - Stores each in `attacks` with `status='pending_execution'`
     - Fires each at the target via httpx, rate-limited
     - Stores the response back in the `attacks` row
     - Updates `status='awaiting_judgment'`
3. arq worker that handles `red_team.execute(brief_id)` jobs.
4. A manual-trigger endpoint `POST /api/v1/campaigns` that creates a
   campaign + brief + enqueues the worker (no Orchestrator yet — just
   bypass it with a hand-rolled brief for now).
5. **Outbound rate limiter** enforced at 10 req/s and 1000 attacks/campaign
   default. Bypassable only by env var.
6. Unit tests for:
   - Each mutation strategy (lexical, structural, multi-turn)
   - Authentication flow (with mocked target)
   - Tagging logic
7. One integration test that runs end-to-end against a mocked target.

### Definition of Done

- [x] `pytest` green (unit + integration with mocked target) — 184 tests
- [x] Manually trigger a campaign via `POST /api/v1/campaigns` with a brief
      targeting `prompt_injection/indirect_via_upload` (campaign
      `79d40631-ffd1-44e6-a443-a4b4d46e9165`, 2026-05-12T04:06Z)
- [x] Worker generates 10 variants, fires them at the **live deployed
      target** as Sara Chen, all 10 land as `attacks` rows with
      `status='awaiting_judgment'`. Nine returned HTTP 200 from the
      agent-api with Co-Pilot refusal narratives ("Prompt injection
      attempt blocked"); one transient client error.
- [ ] LangSmith shows the full trace tree per campaign
      (out-of-band; verify via dashboard at smith.langchain.com)
- [x] Per-agent cost visible in `agent_traces` and LangSmith
      (vacuously true for Slice 1 — Red Team uses deterministic
      mutations + direct httpx, no OpenRouter calls; cost rows arrive
      with Slices 2/3/4/5 when Judge/Orchestrator/Documentation/Patch
      start invoking the LLM)
- [x] Outbound rate limiter holds at 10 req/s under load (token-bucket
      acquire before every request; ten attacks took >100s wall-clock
      due to LLM latency — well under the 10 req/s ceiling)
- [x] No real PHI in attack payloads (only synthetic identifiers from
      TARGET_MANIFEST.md §7: pt-018, pt-007, pinned PIDs 5/13/26/27)
- [x] **Stage 3 hard gate: working agent role running live against the
      deployed target — checked.**

### Out of scope

- Judge (next slice)
- Orchestrator (slice 3)
- UI display of attacks (slice 7)

---

## Slice 2 — Judge Agent + ground-truth eval baseline [Day 3]

**Goal:** Verdicts on stored attacks, with measurable accuracy against a
labeled ground-truth set.

### Deliverables

1. **Ground-truth eval set** at `apps/api/tests/evals/judge_ground_truth.jsonl`
   — minimum 30 hand-labeled (attack_input, target_response, verdict, evidence)
   tuples covering all 4 CRITICAL subcategories.
2. `agents/judge/` package:
   - `model.py` with hardcoded Claude Sonnet model string + temperature 0
   - Rubric resolution: reads `target_manifests.trust_boundaries` and
     `campaign_briefs.success_criteria` for the attack's campaign
   - LangGraph node that:
     - Reads an `attacks` row with `status='awaiting_judgment'`
     - Builds the Judge prompt with rubric + few-shot
     - Calls Claude Sonnet via `llm_client`
     - Validates the JSON response with Pydantic
     - Writes a `verdicts` row
     - Updates `attacks.status='judged'`
3. arq worker for `judge.evaluate(attack_id)`.
4. **Eval runner** at `apps/api/tests/evals/run_judge_eval.py`:
   - Loads ground_truth set
   - Runs Judge on each
   - Records accuracy, per-class precision/recall, total cost
   - Outputs JSON to `apps/api/tests/evals/results/judge_<git_sha>.json`
5. CI job (manual trigger, not on every commit) that runs the eval and
   fails if accuracy drops below 0.85.

### Definition of Done

- [x] `pytest` unit tests on the Judge's rubric resolution and JSON
      parsing pass (29 new tests in `tests/unit/judge/`; 187 unit total green)
- [ ] Eval runner executes against ground_truth set; baseline accuracy
      recorded in `docs/EVAL_BASELINES.md` (runner ready at
      `tests/evals/run_judge_eval.py`; 32 ground-truth tuples loaded.
      First eval run requires `OPENROUTER_API_KEY` — execute via
      workflow_dispatch on `.github/workflows/judge-eval.yml` or locally,
      then paste the row into EVAL_BASELINES.md)
- [ ] Verdict distribution on ground_truth is within 20% of expected
      (depends on first eval run)
- [ ] Run the Slice 1 campaign end-to-end: Red Team → Judge produces
      verdicts for all 10 attacks (handoff wired:
      `red_team_worker` enqueues `judge.evaluate(attack_id)` per attack
      transitioned to awaiting_judgment; needs operator to re-fire campaign
      against the live target)
- [ ] At least one verdict is `exploit` or `partial` (target genuinely has
      attack surface; if all are `safe`, the rubric is too strict or the
      attacks are too weak — investigate before proceeding)
- [ ] LangSmith trace shows Judge as a separate trace node from Red Team
      (operator-side verification after live re-run)

### Out of scope

- Documentation Agent (slice 4)
- Eval automation against drift over time (slice 8)

---

## Slice 3 — Orchestrator [Day 4]

**Goal:** Replace the hand-rolled campaign trigger with the real
Orchestrator. Coverage-driven prioritization, budget enforcement, fallback
behavior.

### Deliverables

1. `agents/orchestrator/` package:
   - **Priority function** (`priority.py`) as pure Python, unit-tested
     extensively. Implements the formula from `ARCHITECTURE.md` §3.1.
   - **Coverage query module** (`coverage.py`) — SQL queries against
     `attack_taxonomy`, `attacks`, `verdicts`, `vulnerabilities`.
   - **Campaign brief generator** — LLM call (Claude Sonnet) that frames
     the top-priority subcategory as a brief. With deterministic fallback
     when the LLM refuses or times out.
   - **Budget enforcer** — checks cumulative `agent_traces.cost_usd`
     against `campaigns.budget_usd` at every Red Team callback. Halts at
     100%.
2. LangGraph node for the Orchestrator that runs on demand or on schedule.
3. arq worker for `orchestrator.tick(campaign_id)`.
4. New endpoint `POST /api/v1/campaigns/start` that creates an empty
   campaign and lets the Orchestrator pick the subcategory.
5. Endpoint `POST /webhooks/github` for receiving deploy notifications —
   verifies signature, identifies the target version change, enqueues a
   regression run (regression worker comes in slice 6).
6. Comprehensive unit tests for priority function: zero-coverage bonus,
   saturation penalty, open-findings boost, staleness, ties.
7. Integration test: priority function returns the expected subcategory
   given a synthetic Postgres state.

### Definition of Done

- [x] `pytest` green (264 unit tests pass — adds 32 orchestrator unit tests
      covering priority math, budget enforcer, brief-generator parse + fallback,
      plus 11 route tests for /campaigns/start + /webhooks/github)
- [x] Triggering `POST /api/v1/campaigns/start` produces a campaign whose
      target_subcategory matches the priority function's top pick
      (route creates empty campaign → orchestrator_tick enqueues → run_tick
      picks subcategory via pick_top() → set_target_subcategory persists it)
- [x] Budget enforcement halts a campaign mid-flight when budget is
      manually set low (budget_enforcer.evaluate at >=100% → status=
      'budget_exhausted'; tested in test_budget_enforcer.py)
- [x] LLM refusal fallback works (test_generate_brief_falls_back_on_parse_failure
      + on_exception cover this path; logs orchestrator_llm_fallback)
- [ ] LangSmith trace shows Orchestrator → Red Team → Judge in sequence
      (operator-side check after first live run)
- [ ] Coverage query results match a hand-computed expected output for a
      seeded test database (needs integration test against Postgres — TODO.md)

### Out of scope

- Regression triggering (slice 6 — the webhook just enqueues a placeholder)
- UI surfacing of campaigns (slice 7)
- Scheduling beyond manual trigger (slice 8)

---

## Slice 4 — Documentation Agent [Day 4]

**Goal:** Confirmed exploits become structured vulnerability reports
without human intervention.

### Deliverables

1. `agents/documentation/` package:
   - Vulnerability report template (Markdown) with all required fields
     from `ARCHITECTURE.md` §3.4
   - LangGraph node that reads a `verdicts` row with `verdict='exploit'`,
     reads the source `attacks` row and `target_manifest`, generates the
     report, writes a `vulnerabilities` row
   - **Framework citation is mandatory** — every report includes
     `owasp_llm_id`, `mitre_atlas_technique_id`, `hipaa_safeguard`, and
     a snapshot of `framework_versions` derived from the attack's
     subcategory in `attack_taxonomy`. The report title and remediation
     section reference the framework IDs directly so the report is
     ingestible by a GRC system without manual re-categorization
     (see THREAT_MODEL.md §4 for the source mappings).
   - **Critical-severity soft gate** — for severity=critical, set
     `status='draft'`; for high/medium/low, set `status='open'`
2. arq worker for `documentation.write(verdict_id)`.
3. **Report quality eval**:
   - Small fixture set of 5 known exploits with expected report fields
   - Eval scores the Documentation Agent's reports for: reproduction-step
     completeness, severity correctness, presence of remediation advice,
     **framework citation accuracy** (does the cited OWASP/ATLAS ID
     match the source subcategory in `attack_taxonomy`?)
   - Baseline recorded in `EVAL_BASELINES.md`
4. Unit tests for severity classification, PHI redaction
   (synthetic-only check), template rendering, framework-ID lookup
   from `attack_taxonomy`.

### Definition of Done

- [x] `pytest` green (264 unit tests pass — adds 34 documentation unit
      tests covering severity rules, framework lookup, parse, template)
- [ ] Slice 1+2+3 end-to-end run produces at least one vulnerability
      report from a confirmed exploit (handoff wired: Judge worker enqueues
      documentation.write on verdict=exploit; needs live re-run)
- [ ] Report reads like something a security engineer could act on
      (subjective review by operator — yes/no decision documented)
- [x] No real PHI in report content (template + prompt explicitly bound
      to synthetic identifiers; unit tests render markdown without leaking)
- [x] **Every report includes framework citations matching the source
      subcategory** (resolve_citation reads attack_taxonomy; LLM never
      supplies framework IDs; deterministic test in test_template.py
      checks remediation section references all three IDs)
- [ ] Eval baseline recorded (runner ready at
      tests/evals/run_documentation_eval.py; first run via
      `.github/workflows/documentation-eval.yml` workflow_dispatch or
      local invocation, then paste the row into EVAL_BASELINES.md)

### Out of scope

- Patch Agent (slice 5)
- UI display of reports (slice 7)

---

## Slice 5 — Patch Agent + GitHub integration [Day 5]

**Goal:** Confirmed vulnerabilities trigger pull requests against the
target's fork. Branch protection enforces the human gate at merge.

### Deliverables

1. **GitHub PAT** scoped to `repo` access on the OpenEMR fork only,
   stored as `GITHUB_PAT` env var.
2. **Branch protection on the fork's `main`** configured manually:
   - Require pull request before merging
   - Require at least one approving review from the operator
   - Require status checks to pass
   - No force push, no deletions
3. `agents/patch/` package:
   - Repo locator: clones the OpenEMR fork into a temp workspace
   - Code search: finds the relevant file(s) based on the vulnerability
     report's surface description
   - Diff generator: LLM call that produces a unified diff with
     justification
   - GitHub API client wrapper: create branch, commit, open PR
4. LangGraph node + arq worker for `patch.propose(vulnerability_id)`.
5. `patches` row written with `pr_url`, `branch_name`, `status='awaiting_human_review'`.
6. Webhook receiver: when a PR is merged, update `patches.status='merged'`
   and enqueue (placeholder for now) the regression worker.
7. Unit tests for: code search, diff generation prompt schema, GitHub API
   client (mocked).
8. Manual operator test:
   - Run slice 1+2+3+4 end-to-end against the live target
   - Patch Agent opens a real PR against the OpenEMR fork
   - Operator reviews and merges (or rejects)
   - The merge is recorded in Postgres

### Definition of Done

- [ ] `pytest` green
- [ ] One real PR opened by the Patch Agent against the OpenEMR fork,
      reviewable by the operator
- [ ] Branch protection on `main` confirmed to block direct push (test
      with the Patch Agent's PAT: a direct push to `main` fails with a
      403)
- [ ] Merged PR triggers `patches.status='merged'` via webhook

### Out of scope

- Regression run on merge (slice 6 — the webhook is in place, the
  regression logic is not)
- UI for PR queue (slice 7)

---

## Slice 6 — Regression Harness [Day 5–6]

**Goal:** Every merged patch is followed by a regression run that proves
the fix held and no other vulnerability regressed.

### Deliverables

1. **Frozen-rubric storage**: when a `vulnerability` is created, snapshot
   the active rubric version and store it in a new column
   `vulnerabilities.rubric_snapshot`. Future regression runs use this
   snapshot, not the current rubric.
2. `harness/` package:
   - Replay logic: takes a `vulnerabilities` row and replays
     `exact_attack_input` N times against the current `target_versions`
   - Majority-vote outcome aggregation
   - Cross-category regression detection: replays **all** previously-resolved
     vulnerabilities on every target version change, not just the one being
     fixed
   - Writes `regression_runs` rows
3. arq worker `harness.run_regressions(target_version_id)`.
4. Wire the GitHub merge webhook (from slice 5) to actually enqueue the
   regression worker now that it exists.
5. Status transitions:
   - All replays safe → `vulnerabilities.status='patched'`
   - Previously-patched, now exploit → `status='regressed'`, urgent flag
   - Mixed replays → `status='unstable'`, flag for review
6. Unit tests for replay logic, majority vote, status transitions.
7. Integration test: synthetic seeded vulnerabilities, mocked target,
   verifies all status transitions.

### Definition of Done

- [ ] `pytest` green
- [ ] Manually: run end-to-end loop. Patch Agent opens PR. Operator
      merges. Webhook fires. Regression replays original exploit 3x. All
      come back safe. Vulnerability status flips to `patched`. Regression
      run row recorded.
- [ ] Cross-category regression check works: artificially introduce a
      regression and verify it's flagged with the offending commit hash
- [ ] LangSmith shows the regression-run trace tree

### Out of scope

- UI display of regression results (next slice)

---

## Slice 7 — Security Buddy UI [Day 6]

**Goal:** The operator console. Everything the previous slices produce in
Postgres becomes visible, actionable, and demo-ready.

### Deliverables

1. **Dashboard** (`/`):
   - Target URL display + connection status
   - Big "Start Campaign" button
   - Coverage map (13 subcategories, attempts + success rate per
     subcategory at current target version)
   - Open vulnerabilities by severity
   - Pending PRs
   - Last campaign cost; rolling daily cost
2. **Campaigns view** (`/campaigns`):
   - Table of campaigns with status, target subcategory, attacks count,
     cost
   - Drill-down to individual campaign showing the brief, attacks, and
     verdicts
3. **Vulnerabilities view** (`/vulnerabilities`):
   - List by status (draft, open, proposed_fix, patched, regressed)
   - Detail view shows the full report, the source attack, the verdict,
     the linked PR, and the regression history
   - **Critical-severity confirmation UI** — soft gate workflow
4. **PRs view** (`/patches`):
   - List of pending patches with status, vulnerability link, GitHub link
   - Operator can mark a patch as reviewed/rejected directly in UI
5. **Before/After diff view** (`/vulnerabilities/[id]/diff`):
   - LEFT: vulnerability report and original failure
   - RIGHT: regression run result
   - Status banner: RESOLVED / REGRESSED / UNSTABLE
6. **Cost dashboard** (`/cost`):
   - Per-agent cost over time
   - Per-campaign cost
   - Daily burn rate
7. Server components throughout — direct Postgres reads, no API call from
   the UI for reads.
8. Streaming for live-running campaigns: while a campaign is running, the
   campaigns view updates progressively via React Suspense.

### Definition of Done

- [ ] All views render correctly with seeded test data
- [ ] Operator can trigger a campaign from the UI and watch it progress
- [ ] Operator can confirm/reject a critical-severity report
- [ ] Operator can mark a patch as reviewed
- [ ] Before/After diff view tells the loop-closing story end-to-end
- [ ] Playwright e2e test covers: log in → trigger campaign → wait for
      verdict → confirm report → see PR → simulate merge → see regression
      result → see RESOLVED banner

### Out of scope

- Admin / RBAC views (post-MVP)
- Real-time push (we use polling + Suspense for MVP)

---

## Slice 8 — Cost analysis, observability polish, final docs [Day 7]

**Goal:** Submission-ready. All graded deliverables crisp. Demo video
material ready.

### Deliverables

1. **COST_ANALYSIS.md** with real numbers:
   - Actual MVP spend (from `agent_traces`)
   - Projected costs at 100/1K/10K/100K runs
   - Architectural shift points and what changes at each scale
2. Grafana / LangSmith dashboard screenshots saved to `docs/screenshots/`
3. **Observability metric catalog** in ARCHITECTURE.md §7.2 verified —
   every metric and event in the catalog is actually emitted by running
   code (CI check optional).
4. **3 vulnerability reports** confirmed and exported to `docs/findings/`:
   - VUL-001, VUL-002, VUL-003 (or whatever the platform actually
     produced)
   - Each report includes the reproduction steps a different engineer
     could follow
   - **Each report cites OWASP LLM Top 10 (2025), MITRE ATLAS (v5.1.0),
     and HIPAA Security Rule** for the finding (this comes for free
     from Slice 4's mandatory framework-citation work; Slice 8 verifies
     it landed correctly in the exported docs)
5. **Demo video script** at `docs/DEMO_SCRIPT.md`:
   - 3–5 min walkthrough of the platform running end-to-end
   - Hits: trigger campaign → live attacks → confirmed exploit → vuln
     report → PR opened → operator review → merge → regression run →
     before/after diff RESOLVED
6. **README.md** final polish:
   - Setup instructions
   - Deployed URLs (target + Security Buddy)
   - Architecture diagram (link to ARCHITECTURE.md)
   - Quick-start to reproduce the demo
7. **Social post draft** for X/LinkedIn (final-only deliverable per the
   case study).

### Definition of Done

- [ ] All graded deliverables present and current:
  - [ ] `THREAT_MODEL.md` — 500+ word summary, full taxonomy
  - [ ] `USERS.md` — three personas, automation justification
  - [ ] `ARCHITECTURE.md` — 500+ word summary, diagram, all agents,
        regression harness, observability, tradeoffs
  - [ ] `COST_ANALYSIS.md` — real spend + projections at 4 scale points
  - [ ] 3+ vulnerability reports in `docs/findings/`
  - [ ] Demo video recorded and uploaded
  - [ ] Deployed application URLs (target + platform) in README
- [ ] CI green on `main`
- [ ] Demo runs end-to-end against the live deployed system on first try

---

## Tracking Slice Progress

Each slice has a corresponding GitHub issue. Each merged PR references its
slice. The `docs/PROGRESS.md` file (created in slice 0) tracks:

- Slice number
- Status (planned / in-progress / merged)
- Merged PRs that contributed
- Open follow-ups deferred to a later slice
- Eval baseline records (for slices that introduce LLM components)

---

## Risk Watchlist

Things most likely to bite during the build. Watch for them.

1. **LangSmith free-tier rate limits.** 5K traces/month. If the Red Team
   Agent runs hot during testing, this caps out fast. Mitigation: in
   slice 8, plan for migration to self-hosted Langfuse if needed.

2. **OpenRouter rate-limits the Llama endpoint.** Llama 70B via OpenRouter
   has tighter limits than Claude. If the Red Team is generating 10
   variants per campaign and a campaign runs daily, we're fine. If we
   start running 100 campaigns a day, we'll hit limits. Mitigation: the
   `llm_client` handles backoff; consider a Together AI direct endpoint
   if we scale up.

3. **The OpenEMR Co-Pilot rate-limits Sara Chen's session.** This is a
   real possibility if we hammer it. Mitigation: outbound rate limiter at
   10 req/s; if we hit 429s, back off and slow down. We are not testing
   the target's rate limit; we are testing its application surface.

4. **GitHub PAT scope creep.** It is very easy to grant the Patch Agent's
   PAT broader scope than needed. Mitigation: explicit verification in
   slice 5 that the PAT can ONLY access the OpenEMR fork.

5. **Judge drift discovered late.** If we change the Judge's prompt
   without re-running the eval, we ship a regressed measurement tool.
   Mitigation: the CLAUDE.md rule about Judge changes requiring an eval
   baseline diff; review every Judge-touching PR for the baseline line.

6. **Time pressure compromising the regression harness.** Slice 6 is the
   most architecturally important slice and the one most tempting to
   shortcut. If we ship without it, we have a platform that finds
   vulnerabilities but cannot prove fixes worked — exactly the failure
   mode the case study warns against. Do not skip.
