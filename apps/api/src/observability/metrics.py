"""Prometheus metric definitions for Security Buddy.

Only the metrics needed at Slice 0 are defined here (llm cost + duration).
The full metric catalog from ARCHITECTURE.md §7.2 is populated in later slices.

Metrics are registered at module import time (prometheus_client does this
automatically for Counter/Histogram objects).
"""

from prometheus_client import Counter, Histogram

# --- LLM cost and latency (Slice 0) ---

LLM_COST_TOTAL = Counter(
    "security_buddy_llm_cost_usd_total",
    "Cumulative LLM cost in USD",
    labelnames=["agent", "model"],
)

LLM_CALL_DURATION = Histogram(
    "security_buddy_llm_call_duration_seconds",
    "LLM call latency in seconds",
    labelnames=["agent", "model"],
    buckets=(0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0),
)

# --- Placeholders for Slice 1+ metrics (not yet instrumented) ---
# ATTACKS_TOTAL          = Counter(...)  # Slice 1
# VERDICTS_TOTAL         = Counter(...)  # Slice 2
# VULNERABILITIES_OPEN   = Gauge(...)    # Slice 4
# REGRESSION_RUNS_TOTAL  = Counter(...)  # Slice 6
# JUDGE_ACCURACY         = Gauge(...)    # Slice 2 eval
