# Security Buddy — Users and Use Cases

**Author:** Hirom Alarcon
**Week:** 3 — Gauntlet AI Austin Admission Track

---

## 1. Who Security Buddy Is For

Security Buddy is built for the people responsible for keeping AI-assisted
clinical systems trustworthy over time. That responsibility shows up in
three distinct shapes, depending on the organization — sometimes a single
person carries all three hats, sometimes the work is distributed across a
small team. In either case, the platform is designed around three personas
whose workflows it has to support.

The personas below are real roles in healthcare technology organizations.
The MVP serves all three through a single operator account behind a
password gate; multi-user RBAC is deferred to a later phase, but the
platform's data model and design anticipate it.

---

## 2. Persona 1 — The AI Security Engineer

### Profile

A security engineer at a healthcare technology company, or a security
researcher consulting to one. They are technical, comfortable with both
traditional application security (OWASP, threat modeling) and the
particular failure modes of LLM-driven systems (prompt injection, indirect
injection, multi-turn manipulation, persona drift).

### Their job

Continuously evaluate the security posture of an AI-assisted clinical
product. Find vulnerabilities. Drive them through to verified fixes. Show
leadership and compliance auditors evidence that the product is becoming
more resilient, not less, as it ships features.

### What they need from Security Buddy

- **Autonomy.** They cannot personally write a hundred adversarial prompts
  a week against every new build. The Red Team Agent does the volume work;
  they review findings and direct strategy.
- **Reproducibility.** When they file a vulnerability, the report must be
  precise enough that an engineer on another team can reproduce it without
  the security engineer in the room. The Documentation Agent's reports
  meet this bar by design.
- **Regression confidence.** When they sign off on a fix, they need to
  know it will be retested automatically on every future deployment. The
  Regression Harness gives them that without manual intervention.
- **Coverage visibility.** They need to defend "we tested X, we know
  about gap Y, here's our plan for Z" to leadership. The coverage
  dashboard answers all three.
- **Cost predictability.** Continuous testing at scale gets expensive
  fast. They need per-campaign and per-day cost data, and circuit breakers
  that prevent runaway spend.
- **Framework-aligned findings.** They need the platform's reports to map
  to taxonomies their organization already uses — OWASP LLM Top 10
  (2025), MITRE ATLAS, and HIPAA — so findings slot into the GRC tools
  and audit workflows their organization already runs without manual
  re-categorization.

### Their primary workflow

```
Monday morning:
  1. Open Security Buddy. Review weekend campaigns.
  2. Triage new vulnerability reports (confirm or reject critical
     severity, leave high/medium as auto-confirmed).
  3. Review pending Patch Agent PRs. Merge the obvious wins. Request
     changes on the questionable ones.
  4. Watch regression suite re-verify merged fixes.
  5. Glance at the coverage map. Identify under-tested subcategories.
     Bias next week's Orchestrator priorities toward them.
```

### Why automation is the right solution for them

Manual adversarial testing does not scale to continuous deployment.
A security engineer might write 10 high-quality attacks per day. A
properly-tuned Red Team Agent generates and tests hundreds per day at a
small fraction of the cost. The security engineer's expertise is best
spent on judgment calls — confirming critical findings, reviewing patch
diffs, directing strategy — not on payload generation.

The case study is direct about this:

> *"Static payload lists become outdated quickly. Defenses built around a
> small number of known examples rarely hold as attackers adapt."*

A human writing payloads is, by definition, producing a static list as of
the moment they wrote it. The platform's value is that its attack
generation evolves continuously.

---

## 3. Persona 2 — The Engineering Manager

### Profile

An engineering manager responsible for the AI-assisted product itself.
Technical enough to read a vulnerability report and understand the fix,
but not focused on security as their primary job. They care about ship
velocity, code quality, on-call burden, and customer trust.

### Their job

Decide when a security finding blocks a release and when it ships with a
follow-up ticket. Allocate engineering time to fixes. Defend the product's
security posture to internal stakeholders. Make sure the team is not
shipping vulnerabilities they could have caught.

### What they need from Security Buddy

- **Triaged findings, not raw signal.** They open the dashboard and see
  three critical, twelve high, seven medium — not three thousand attempts.
  The Judge does the filtering.
- **Patch proposals with rationale.** Reading a PR with a code diff plus
  the vulnerability report it addresses is far faster than reading the
  report alone. The Patch Agent's PRs are designed to be reviewable in
  under five minutes by someone who understands the codebase.
- **Trend lines.** "Are we getting more secure?" is the question they
  actually need to answer. The before-and-after diff view, and the
  coverage map over time, are designed for this.
- **No surprises.** They do not want to learn from a customer or a
  reporter that their product leaked PHI. They want to learn from Security
  Buddy first, with a draft fix already proposed.

### Their primary workflow

```
End of each sprint:
  1. Open Security Buddy. Look at vulnerabilities discovered this sprint.
  2. Look at which were already patched (auto-handled by the loop).
  3. Look at which are still open and assign engineering time.
  4. Look at the trend: are we accumulating debt or paying it down?
  5. Sign off on the security posture for the sprint review.
```

### Why automation is the right solution for them

An engineering manager cannot personally read every vulnerability finding
in detail every week. They need a layer of curation that flags what
genuinely matters, drafts the response, and gives them a single decision
point: approve or reject. That curation is exactly what the
Documentation and Patch agents provide.

Equally important: an engineering manager will not personally run weekly
regression suites. Without automation, the regression suite decays — and a
decayed regression suite is worse than none, because it provides false
assurance. The Orchestrator's deploy-triggered regression run keeps the
suite alive without requiring human action.

---

## 4. Persona 3 — The Compliance / Healthcare CISO

### Profile

A Chief Information Security Officer or compliance lead at a healthcare
organization (or at a vendor selling AI tooling into one). They are
responsible for the organization's regulatory posture (HIPAA, HITRUST,
state-level requirements) and for the trust relationship with clinical
leadership and patients.

### Their job

Decide whether to trust the AI-assisted product with patient data, and
defend that decision to auditors, the board, and (potentially) regulators.
Evaluate vendors. Sign off on production deployments.

### What they need from Security Buddy

- **Evidence, not assertions.** A vendor saying "we test our AI for
  security" is meaningless. A vendor showing a coverage map with 13
  attack subcategories, attempts and outcomes per subcategory across
  versions, time-to-detection per vulnerability, and time-to-fix is
  evidence.
- **Evidence in the language regulators and auditors speak.** Every
  finding maps to OWASP LLM Top 10 (the practitioner-level taxonomy),
  MITRE ATLAS (the threat-modeling rigor), and the HIPAA Security Rule
  safeguard it implicates. A report citing `LLM01:2025 / AML.T0051.001 /
  HIPAA § 164.312(a)(1)` is immediately mappable to the organization's
  existing risk register. A report describing "a kind of prompt
  injection thing" is not.
- **Audit trail.** Every attack, every verdict, every fix, every
  regression run is durable in Postgres and reconstructable via SQL. This
  is the artifact compliance asks for.
- **A clear story about trust boundaries.** Where does the platform stop
  and ask a human? Where does autonomy end? The hard human gate at patch
  merge is the answer they need to hear.
- **Cost transparency.** Compliance often controls budgets. Knowing the
  platform's spend profile, and that spend is capped at the application
  layer rather than trusted to LLM self-restraint, makes the budget
  conversation a real one.

### Their primary workflow

```
Quarterly review:
  1. Pull the coverage report from Security Buddy.
  2. Cross-reference open vulnerabilities against severity SLAs.
  3. Verify that resolved vulnerabilities have regression coverage.
  4. Verify cost is within budgeted bounds.
  5. Document for the audit file.
```

The CISO will rarely log in to Security Buddy in week-to-week operations.
They will look at it during quarterly reviews, during incident response,
during vendor audits, and during procurement decisions. The platform's
job for them is to make those moments fast and defensible.

### Why automation is the right solution for them

The case study sets the bar explicitly:

> *"The deliverable that matters is not the one that finds the most
> impressive jailbreak in a demo. It's the one you could defend in front
> of a hospital CISO who is deciding whether to trust this platform with
> continuous security testing of systems their physicians depend on."*

A CISO does not want to trust an ad-hoc human red team that does work in
bursts. They want a system whose evidence accumulates. The platform is
designed to be that system.

---

## 5. Operator Workflow (MVP)

In the MVP, all three personas are served by a single operator account
(the platform builder, in initial deployment). The operator's workflow
combines elements of all three personas:

```
Daily:
  • Open Security Buddy
  • Review new vulnerability reports flagged for confirmation
  • Review pending Patch Agent PRs
  • Merge approved fixes
  • Watch regression suite verify the fixes held

Weekly:
  • Review coverage map for gaps
  • Adjust Orchestrator priority weights if needed
  • Check cost burn against budget
  • Add new seed attacks to subcategories that are under-tested

On every target deploy:
  • Platform auto-triggers regression suite
  • Operator reviews any regressions flagged
  • Operator decides whether the regression blocks the deploy

On a new attack technique published:
  • Operator adds a new seed attack to the relevant subcategory
  • Red Team Agent incorporates it into its mutation library
  • Coverage of the subcategory effectively resets at the new version
```

---

## 6. What This Platform Is Not For

Naming explicitly:

- **Not for testing arbitrary third-party systems.** The platform attacks
  one configured target. The operator owns or is authorized to test that
  target. Pointing it at someone else's system without authorization is
  outside the platform's intended use and outside the operator's authority.
- **Not for general-purpose penetration testing.** Network scanning,
  filesystem fuzzing, dependency CVE auditing — these are existing
  disciplines with existing tools. Security Buddy targets the
  application-layer adversarial surface of AI-assisted workflows, not
  the broader infosec surface.
- **Not for replacing human security review entirely.** The human gate
  at patch merge is deliberate. Critical-severity reports stay in draft
  until human-confirmed. The platform makes the human's work more
  effective; it does not eliminate it.
- **Not a one-time audit tool.** The value is continuous. A single
  campaign produces a few findings; six months of continuous campaigns
  produces a measurable resilience trend. The platform's design assumes
  the latter use case, not the former.

---

## 7. Cross-References

- `ARCHITECTURE.md` — how the platform's agents support each persona's
  workflow
- `THREAT_MODEL.md` — the attack surface each persona's findings will
  cover
- `docs/PLAN.md` — build order, including which UI surfaces serve which
  persona first
