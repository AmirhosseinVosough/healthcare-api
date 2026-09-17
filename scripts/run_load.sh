#!/usr/bin/env bash
# Step through concurrency levels against a freshly started server.
# Usage: scripts/run_load.sh <label> [extra uvicorn args...]
set -u
LABEL="${1:-baseline}"; shift || true
PORT=8500
OUT="loadtest/$LABEL"
mkdir -p "$OUT"

pkill -f "uvicorn app.main:app --port $PORT" 2>/dev/null
lsof -ti tcp:$PORT | xargs kill -9 2>/dev/null

RATE_LIMIT_ENABLED=false .venv/bin/uvicorn app.main:app --port $PORT \
  --log-level warning "$@" > "$OUT/server.log" 2>&1 &
curl -s --retry 30 --retry-delay 1 --retry-connrefused -o /dev/null http://127.0.0.1:$PORT/health || exit 1

for USERS in 10 25 50 100 200 400; do
  echo "  ${USERS} users..."
  .venv/bin/locust -f locustfile.py --headless \
    -u "$USERS" -r "$((USERS / 5 + 1))" -t 30s \
    --host "http://127.0.0.1:$PORT" \
    --csv "$OUT/u$USERS" --only-summary > "$OUT/u$USERS.log" 2>&1
done

lsof -ti tcp:$PORT | xargs kill -9 2>/dev/null
echo "  done -> $OUT"
