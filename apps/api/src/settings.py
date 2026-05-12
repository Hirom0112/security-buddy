"""Application settings — all secrets come from environment variables.

Missing any REQUIRED variable causes startup failure. There are no fallback
defaults for secrets. This is intentional and non-negotiable (CLAUDE.md §2).
"""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Pydantic BaseSettings with no fallback defaults for secrets.

    Required fields have no default value; startup fails if they are absent.
    Optional fields (Slice 1+ only) default to None.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="forbid",
        case_sensitive=False,
    )

    # --- Required (no defaults) ---
    database_url: str = Field(
        description="Async Postgres connection string (postgresql+asyncpg://...)"
    )
    redis_url: str = Field(description="Redis connection string (redis://...)")
    openrouter_api_key: str = Field(description="OpenRouter API key — no fallback")
    langsmith_api_key: str = Field(
        description="LangSmith API key, or the literal string 'DISABLED' to skip tracing"
    )
    langsmith_project: str = Field(description="LangSmith project name")
    session_secret: str = Field(
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
    target_login_password: str | None = Field(
        default=None,
        description="Password for target login",
    )
    github_pat: str | None = Field(
        default=None,
        description="GitHub PAT scoped to the OpenEMR fork only (repo scope)",
    )

    @property
    def langsmith_disabled(self) -> bool:
        """Return True if LangSmith tracing is explicitly disabled."""
        return self.langsmith_api_key.upper() == "DISABLED"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the singleton Settings instance (lazily instantiated).

    Raises ValidationError on first call if any required env var is missing.
    Using lru_cache ensures the validation happens once at startup.
    """
    return Settings()
