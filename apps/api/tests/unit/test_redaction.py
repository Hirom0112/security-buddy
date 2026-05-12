"""Unit tests for the secret redaction utility.

Coverage:
  - Pattern-based string scrubbing (sk-, gho_, glpat-, JWT, Bearer)
  - Dict key scrubbing for sensitive field names
  - Recursive scrubbing through nested structures
  - Non-sensitive values pass through unchanged
  - Type fidelity (list in → list out, dict in → dict out)
"""

from src.llm_client.redaction import redact

_REDACTED = "<redacted>"


class TestStringPatterns:
    def test_scrubs_openrouter_key(self) -> None:
        result = redact("sk-or-v1-abcdefghijklmnopqrstuvwxyz123456")
        assert result == _REDACTED

    def test_scrubs_openai_style_key(self) -> None:
        result = redact("sk-abcdefghijklmnopqrstuvwxyz1234567890")
        assert result == _REDACTED

    def test_scrubs_github_oauth_token(self) -> None:
        result = redact("gho_" + "a" * 36)
        assert result == _REDACTED

    def test_scrubs_gitlab_pat(self) -> None:
        result = redact("glpat-abc123def456ghi789jkl012mno345")
        assert result == _REDACTED

    def test_scrubs_jwt(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.signature123abc"
        result = redact(jwt)
        assert result == _REDACTED

    def test_scrubs_bearer_token(self) -> None:
        result = redact("Bearer sk-supersecrettoken12345")
        assert _REDACTED in result

    def test_plain_string_unchanged(self) -> None:
        result = redact("hello world, no secrets here")
        assert result == "hello world, no secrets here"

    def test_scrubs_key_within_longer_string(self) -> None:
        text = "Using key sk-abcdefghijklmnopqrstuvwxyz1234567890 for auth"
        result = redact(text)
        assert "sk-" not in result
        assert _REDACTED in result


class TestDictKeyRedaction:
    def test_password_key_redacted(self) -> None:
        result = redact({"password": "mysecretpassword"})
        assert result == {"password": _REDACTED}

    def test_secret_key_redacted(self) -> None:
        result = redact({"session_secret": "abc123"})
        assert result == {"session_secret": _REDACTED}

    def test_token_key_redacted(self) -> None:
        result = redact({"access_token": "bearer-value"})
        assert result == {"access_token": _REDACTED}

    def test_api_key_redacted(self) -> None:
        result = redact({"api_key": "some-key"})
        assert result == {"api_key": _REDACTED}

    def test_authorization_key_redacted(self) -> None:
        result = redact({"authorization": "Bearer tok"})
        assert result == {"authorization": _REDACTED}

    def test_api_dash_key_redacted(self) -> None:
        result = redact({"api-key": "value"})
        assert result == {"api-key": _REDACTED}

    def test_non_sensitive_key_unchanged(self) -> None:
        result = redact({"model": "claude-3", "duration_ms": 123.4})
        assert result == {"model": "claude-3", "duration_ms": 123.4}

    def test_case_insensitive_key_matching(self) -> None:
        result = redact({"PASSWORD": "secret"})
        assert result == {"PASSWORD": _REDACTED}


class TestNestedStructures:
    def test_nested_dict_recursed(self) -> None:
        result = redact({"outer": {"password": "secret", "ok": "fine"}})
        assert result == {"outer": {"password": _REDACTED, "ok": "fine"}}

    def test_list_of_strings_scrubbed(self) -> None:
        result = redact(["hello", "sk-abcdefghijklmnopqrstuvwxyz12345"])
        assert result[0] == "hello"
        assert result[1] == _REDACTED

    def test_list_of_dicts_recursed(self) -> None:
        result = redact([{"password": "secret"}, {"model": "gpt-4"}])
        assert result[0] == {"password": _REDACTED}
        assert result[1] == {"model": "gpt-4"}

    def test_tuple_treated_as_list(self) -> None:
        result = redact(("hello", "gho_" + "a" * 36))
        assert isinstance(result, list)
        assert result[0] == "hello"
        assert result[1] == _REDACTED

    def test_deeply_nested(self) -> None:
        result = redact({"a": {"b": {"password": "deep_secret"}}})
        assert result == {"a": {"b": {"password": _REDACTED}}}


class TestPassThrough:
    def test_int_unchanged(self) -> None:
        assert redact(42) == 42

    def test_float_unchanged(self) -> None:
        assert redact(3.14) == 3.14

    def test_none_unchanged(self) -> None:
        assert redact(None) is None

    def test_bool_unchanged(self) -> None:
        assert redact(True) is True

    def test_empty_dict_unchanged(self) -> None:
        assert redact({}) == {}

    def test_empty_list_unchanged(self) -> None:
        assert redact([]) == []
