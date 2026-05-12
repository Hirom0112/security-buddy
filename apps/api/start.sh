#!/usr/bin/env bash
set -euo pipefail

ROLE="${SERVICE_ROLE:-api}"

case "$ROLE" in
  worker)
    exec arq src.workers.WorkerSettings
    ;;
  api|*)
    alembic upgrade head
    exec uvicorn src.main:app --host 0.0.0.0 --port "${PORT:-8000}"
    ;;
esac
