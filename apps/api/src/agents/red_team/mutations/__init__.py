"""Mutation strategies for the Red Team agent.

Each strategy is a pure function of (SeedAttack, count, rng_seed) → list[Variant].
No I/O, no global mutable state, no subprocess, no os.system.

Strategies are deterministic for Slice 1 — same inputs always produce the
same outputs. LLM-driven mutation may be added in Slice 1b+.
"""
