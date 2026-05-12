"""Unit tests for Settings — verifies startup failure on missing required vars."""

import typing

import pytest
from pydantic import ValidationError

# We must clear the lru_cache between tests so each test gets a fresh instance.
from src import settings as settings_module


def _clear_cache() -> None:
    settings_module.get_settings.cache_clear()


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
        settings = settings_module.get_settings()
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
            settings_module.get_settings()


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
        for var in ("TARGET_BASE_URL", "TARGET_LOGIN_USER", "TARGET_LOGIN_PASSWORD", "GITHUB_PAT"):
            monkeypatch.delenv(var, raising=False)

        settings = settings_module.get_settings()
        assert settings.target_base_url is None
        assert settings.target_login_user is None
        assert settings.target_login_password is None
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
        settings = settings_module.get_settings()
        assert settings.langsmith_disabled is True

    def test_langsmith_disabled_property_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for key, val in TestSettingsRequiredVars.REQUIRED_VARS.items():
            monkeypatch.setenv(key, val)
        monkeypatch.setenv("LANGSMITH_API_KEY", "ls-some-real-key-12345")
        settings = settings_module.get_settings()
        assert settings.langsmith_disabled is False
