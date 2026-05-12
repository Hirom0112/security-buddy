"""Alembic environment — async migration runner.

Reads the database URL from the Pydantic settings module so that no secrets
are ever hardcoded in config files (CLAUDE.md §2).

Uses the run_async_migrations pattern required for asyncpg / SQLAlchemy async.
"""

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

# Pull the database URL from Pydantic settings — the only authoritative source.
# get_settings() will raise ValidationError if DATABASE_URL is missing from env,
# which is the desired behavior (fail fast, not silently).
from src.settings import get_settings

# Alembic Config object — gives access to values in alembic.ini.
config = context.config

# Set up Python logging from the alembic.ini [loggers] section.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Inject the database URL at runtime from Pydantic settings.
# This overrides the (absent) sqlalchemy.url in alembic.ini.
settings = get_settings()
config.set_main_option("sqlalchemy.url", settings.database_url.get_secret_value())

# target_metadata is None because we rely on raw Alembic ops (op.create_table,
# op.add_column, etc.) in each migration rather than autogenerate from models.
# If we later add SQLAlchemy ORM models with a Base, set target_metadata = Base.metadata.
target_metadata = None


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    Configures the context with just a URL and not an Engine; a Connection is
    not required. Migrations are emitted to stdout as SQL (useful for DBA review).
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """Execute migrations against the provided connection."""
    context.configure(connection=connection, target_metadata=target_metadata)

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations using an async engine.

    Creates an async engine from the alembic config (which has the URL injected
    from Pydantic settings above), then hands a sync connection to Alembic's
    context manager via run_sync.
    """
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Entry point for online migrations — runs the async runner."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
