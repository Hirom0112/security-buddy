"""Application settings — all secrets come from environment variables.

Missing any REQUIRED variable causes startup failure. There are no fallback
defaults for secrets. This is intentional and non-negotiable (CLAUDE.md §2).

Secret fields use `pydantic.SecretStr` so they never appear in `repr()`,
tracebacks, or logs. Accessing the secret value requires an explicit
`.get_secret_value()` call. This is a hard requirement after a leak via a
pytest assertion-error repr (incident: 2026-05-12).
"""

from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Pydantic BaseSettings with no fallback defaults for secrets.

    Required fields have no default value; startup fails if they are absent.
    Optional fields (Slice 1+ only) default to None.

    Secret-bearing fields are typed `SecretStr` and must be unwrapped via
    `.get_secret_value()` at the call site — never logged, never printed.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="forbid",
        case_sensitive=False,
    )

    # --- Required (no defaults) ---
    database_url: SecretStr = Field(
        description="Async Postgres connection string (postgresql+asyncpg://...)"
    )
    redis_url: str = Field(description="Redis connection string (redis://...)")
    openrouter_api_key: SecretStr = Field(description="OpenRouter API key — no fallback")
    langsmith_api_key: SecretStr = Field(
        description="LangSmith API key, or the literal string 'DISABLED' to skip tracing"
    )
    langsmith_project: str = Field(description="LangSmith project name")
    session_secret: SecretStr = Field(
        description="Secret key for session cookies — must be a random 32+ byte hex string"
    )

    # --- Optional (Slice 1+ only, acceptable as None for Slice 0) ---
    target_base_url: str | None = Field(
        default=None,
        description="Base URL of the OpenEMR Clinical Co-Pilot target",
    )
    target_login_user: str | None = Field(
        default=None,
        description="Username for authenticating against the target (Sara Chen)",
    )
    target_login_password: SecretStr | None = Field(
        default=None,
        description="Password for target login",
    )
    target_openemr_url: str | None = Field(
        default=None,
        description="Base URL of the OpenEMR PHP application (for PHP login + JWT extraction)",
    )
    target_copilot_module_path: str | None = Field(
        default=None,
        description="Path to the OpenEMR Co-Pilot module page (for JWT extraction)",
    )
    github_pat: SecretStr | None = Field(
        default=None,
        description="GitHub PAT scoped to the OpenEMR fork only (repo scope)",
    )
    github_webhook_secret: SecretStr | None = Field(
        default=None,
        description=(
            "Shared secret for the GitHub merge webhook (HMAC SHA-256). "
            "When None, the webhook route refuses all deliveries — fail-closed."
        ),
    )

    @property
    def langsmith_disabled(self) -> bool:
        """Return True if LangSmith tracing is explicitly disabled."""
        return self.langsmith_api_key.get_secret_value().upper() == "DISABLED"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the singleton Settings instance (lazily instantiated).

    Raises ValidationError on first call if any required env var is missing.
    Using lru_cache ensures the validation happens once at startup.
    """
    return Settings()
