#!/usr/bin/env bash
# Start the dashboard on http://127.0.0.1:8000
cd "$(dirname "$0")"
exec uvicorn app.main:app --host "${HOST:-127.0.0.1}" --port "${PORT:-8000}"
