"""Unit tests for the response-shape hash used by Documentation Agent dedup.

The hash collapses volatile primitives (numbers, dates, UUIDs, raw strings)
into stable type tokens so two responses with the same *shape* but different
*values* hash identically. This is the dedup key (PLAN.md "Documentation:
pre-write 3-replay + response-shape dedup").
"""

from __future__ import annotations

import json

from src.agents.documentation.document import _response_shape_hash


def test_same_shape_different_numeric_values_hash_identically() -> None:
    """The 9-permutation incident: same response shape, different numbers."""
    a = json.dumps({"narrative": "TSH for patient 12345 on 2026-01-01 is 2.3", "hr": 72})
    b = json.dumps({"narrative": "TSH for patient 99999 on 2026-05-15 is 4.1", "hr": 88})
    assert _response_shape_hash(a) == _response_shape_hash(b)


def test_different_keys_hash_differently() -> None:
    """Different structural keys must NOT collide."""
    a = json.dumps({"narrative": "x", "vitals": {}})
    b = json.dumps({"narrative": "x", "labs": {}})
    assert _response_shape_hash(a) != _response_shape_hash(b)


def test_uuids_are_normalized() -> None:
    """A UUID in the response body must not differentiate two shapes."""
    a = "patient 11111111-1111-1111-1111-111111111111 has TSH 2.3"
    b = "patient 22222222-2222-2222-2222-222222222222 has TSH 9.9"
    assert _response_shape_hash(a) == _response_shape_hash(b)


def test_dates_are_normalized() -> None:
    """ISO dates and timestamps must collapse to the same DATE token."""
    a = "labs drawn at 2026-01-01T12:00:00Z"
    b = "labs drawn at 2026-05-15T08:30:00+00:00"
    assert _response_shape_hash(a) == _response_shape_hash(b)


def test_empty_response_is_stable() -> None:
    """Empty input still hashes to something deterministic."""
    h1 = _response_shape_hash("")
    h2 = _response_shape_hash("")
    assert h1 == h2
    assert len(h1) == 16


def test_hash_length_is_16_hex_chars() -> None:
    h = _response_shape_hash('{"a": 1}')
    assert len(h) == 16
    int(h, 16)  # parses as hex


def test_key_order_does_not_matter() -> None:
    """{a,b} and {b,a} must hash identically."""
    a = json.dumps({"alpha": 1, "beta": 2})
    b = json.dumps({"beta": 2, "alpha": 1})
    assert _response_shape_hash(a) == _response_shape_hash(b)


def test_completely_different_shapes_differ() -> None:
    a = json.dumps({"narrative": "x", "vitals": {"hr": 72}})
    b = json.dumps({"error": "denied"})
    assert _response_shape_hash(a) != _response_shape_hash(b)


def test_text_fallback_when_not_json() -> None:
    """Non-JSON input is hashed via _normalize_text — still stable, still scrubs numbers."""
    a = "ALERT 12345 fired at 2026-01-01"
    b = "ALERT 99999 fired at 2026-05-15"
    assert _response_shape_hash(a) == _response_shape_hash(b)
