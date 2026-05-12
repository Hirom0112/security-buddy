# Security Buddy API

FastAPI backend for the Security Buddy adversarial evaluation platform.

See the [repository root README](../../README.md) for full setup and architecture.

## Dev commands

```bash
# Install dependencies (requires uv)
uv sync

# Run API server
uv run uvicorn src.main:app --reload

# Run arq worker (separate terminal)
uv run arq src.workers.WorkerSettings

# Static analysis
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy src
uv run lint-imports

# Tests
uv run pytest tests/unit -v          # unit only (fast)
uv run pytest tests/integration -v  # requires Postgres + Redis
uv run pytest tests/evals -m eval   # LLM evals (slow, costs money)
uv run pytest --cov=src --cov-report=term-missing
```

## Environment variables

Copy `.env.example` to `.env` and fill in all required values.
The service **refuses to start** if any required variable is missing.
