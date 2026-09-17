#!/usr/bin/env bash
# Runs at container start: bring the schema up to date, then serve.
set -euo pipefail

# Apply any migrations the running image is ahead of. Safe to run every start —
# alembic does nothing when the database is already current. One container does
# this cleanly; a fleet needs it run as a separate step before rollout, noted
# in docs/deploy.md.
echo "==> applying migrations"
alembic upgrade head

# --no-proxy-headers is not optional. Without it uvicorn does its own, looser
# version of trusting X-Forwarded-For before our code runs, which undoes the
# per-caller rate limit. Our own caller_address does the trusting, governed by
# TRUSTED_PROXY_IPS.
#
# Workers default to 1. Raise WEB_CONCURRENCY only after checking the pool
# arithmetic in docs/deploy.md: (pool_size + max_overflow) x workers must stay
# under the database's connection limit.
echo "==> starting server"
exec uvicorn app.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --no-proxy-headers \
  --workers "${WEB_CONCURRENCY:-1}" \
  --no-server-header
