"""Regression harness — Slice 6.

Replays previously-confirmed exploits against the current target after a
patch merges. Aggregates per-replay verdicts into a regression outcome
and transitions vulnerability status (patched | regressed | unstable).

Architectural notes:
  - The harness/ package is the *integration layer* for regression: it
    is allowed to import from agents/ (Judge, Red Team's TargetClient)
    and from repositories/. Mirrors the workers/ package in that sense.
  - The harness uses the *frozen rubric* from vulnerabilities.rubric_snapshot
    (set at Documentation-Agent write time). New rubric drift cannot
    re-grade an old finding.
"""
