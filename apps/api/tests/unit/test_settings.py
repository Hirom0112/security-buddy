"""Unit tests for Settings — verifies startup failure on missing required vars.

Tests bypass the on-disk `.env` file by passing `_env_file=None` directly to
`Settings(...)`. Without this, any developer machine that has a real `.env`
will see those values bleed into the test process for fields the test didn't
monkeypatch — a leak risk previously exploited by a pytest traceback that
exposed `github_pat` (incident: 2026-05-12). Tests must be hermetic.
"""

import typing

import pytest
from pydantic import SecretStr, ValidationError

from src import settings as settings_module


def _clear_cache() -> None:
    settings_module.get_settings.cache_clear()


def _new_settings_without_dotenv() -> settings_module.Settings:
    """Construct Settings reading ONLY the (monkeypatched) process env.

    Pydantic supports `_env_file=None` to disable file loading at construction
    time — preferred over editing the class-level `model_config` because that
    would change production behaviour.
    """
    return settings_module.Settings(_env_file=None)  # type: ignore[call-arg]


class TestSettingsRequiredVars:
    """Every required var must be present; missing any one causes ValidationError."""

    REQUIRED_VARS: typing.ClassVar[dict[str, str]] = {
        "DATABASE_URL": "postgresql+asyncpg://test:test@localhost/test",
        "REDIS_URL": "redis://localhost:6379/0",
        "OPENROUTER_API_KEY": "sk-test-fake-key-not-real",
        "LANGSMITH_API_KEY": "DISABLED",
        "LANGSMITH_PROJECT": "test-project",
        "SESSION_SECRET": "a" * 64,
    }

    def setup_method(self) -> None:
        _clear_cache()

    def teardown_method(self) -> None:
        _clear_cache()

    def test_all_required_vars_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for key, val in self.REQUIRED_VARS.items():
            monkeypatch.setenv(key, val)
        settings = _new_settings_without_dotenv()
        assert settings.langsmith_project == "test-project"

    @pytest.mark.parametrize("missing_var", list(REQUIRED_VARS.keys()))
    def test_missing_var_raises(self, monkeypatch: pytest.MonkeyPatch, missing_var: str) -> None:
        """Startup must fail if any single required var is absent."""
        for key, val in self.REQUIRED_VARS.items():
            if key == missing_var:
                monkeypatch.delenv(key, raising=False)
            else:
                monkeypatch.setenv(key, val)

        with pytest.raises(ValidationError):
            _new_settings_without_dotenv()


class TestSettingsOptionalVars:
    """Optional vars (Slice 1+) default to None, not to any credential."""

    def setup_method(self) -> None:
        _clear_cache()

    def teardown_method(self) -> None:
        _clear_cache()

    def test_optional_vars_default_to_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for key, val in TestSettingsRequiredVars.REQUIRED_VARS.items():
            monkeypatch.setenv(key, val)
        # Ensure optional vars are NOT set
        for var in (
            "TARGET_BASE_URL",
            "TARGET_LOGIN_USER",
            "TARGET_LOGIN_PASSWORD",
            "TARGET_OPENEMR_URL",
            "TARGET_COPILOT_MODULE_PATH",
            "GITHUB_PAT",
        ):
            monkeypatch.delenv(var, raising=False)

        settings = _new_settings_without_dotenv()
        assert settings.target_base_url is None
        assert settings.target_login_user is None
        assert settings.target_login_password is None
        assert settings.target_openemr_url is None
        assert settings.target_copilot_module_path is None
        assert settings.github_pat is None


class TestLangsmithDisabled:
    def setup_method(self) -> None:
        _clear_cache()

    def teardown_method(self) -> None:
        _clear_cache()

    def test_langsmith_disabled_property_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for key, val in TestSettingsRequiredVars.REQUIRED_VARS.items():
            monkeypatch.setenv(key, val)
        monkeypatch.setenv("LANGSMITH_API_KEY", "DISABLED")
        settings = _new_settings_without_dotenv()
        assert settings.langsmith_disabled is True

    def test_langsmith_disabled_property_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for key, val in TestSettingsRequiredVars.REQUIRED_VARS.items():
            monkeypatch.setenv(key, val)
        monkeypatch.setenv("LANGSMITH_API_KEY", "ls-some-real-key-12345")
        settings = _new_settings_without_dotenv()
        assert settings.langsmith_disabled is False


class TestSecretsRedactedInRepr:
    """SecretStr fields MUST NOT appear in repr/str — regression guard for the
    2026-05-12 pytest-traceback leak incident.
    """

    def setup_method(self) -> None:
        _clear_cache()

    def teardown_method(self) -> None:
        _clear_cache()

    def test_secret_fields_redacted_in_repr(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for key, val in TestSettingsRequiredVars.REQUIRED_VARS.items():
            monkeypatch.setenv(key, val)
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-LEAKABLE-VALUE-XYZ")
        monkeypatch.setenv("SESSION_SECRET", "SECRET-SESSION-LEAKABLE-VALUE")
        monkeypatch.setenv("GITHUB_PAT", "github_pat_LEAKABLE_VALUE_XYZ")
        monkeypatch.setenv("TARGET_LOGIN_PASSWORD", "LEAKABLE-PASSWORD")

        settings = _new_settings_without_dotenv()
        rendered = repr(settings) + str(settings)

        for leakable in (
            "sk-or-v1-LEAKABLE-VALUE-XYZ",
            "SECRET-SESSION-LEAKABLE-VALUE",
            "github_pat_LEAKABLE_VALUE_XYZ",
            "LEAKABLE-PASSWORD",
        ):
            assert leakable not in rendered, (
                f"SECRET LEAK: {leakable!r} appears in Settings repr/str"
            )

        # Values are still reachable via .get_secret_value() — typed access only.
        assert isinstance(settings.openrouter_api_key, SecretStr)
        assert settings.openrouter_api_key.get_secret_value() == "sk-or-v1-LEAKABLE-VALUE-XYZ"
