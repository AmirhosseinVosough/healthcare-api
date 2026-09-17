#!/usr/bin/env bash
set -u
LABEL="$1"; WORKERS="$2"
PORT=8501
OUT="loadtest/$LABEL"; mkdir -p "$OUT"
lsof -ti tcp:$PORT | xargs kill -9 2>/dev/null
RATE_LIMIT_ENABLED=false .venv/bin/uvicorn app.main:app --port $PORT \
  --log-level warning --workers "$WORKERS" > "$OUT/server.log" 2>&1 &
curl -s --retry 30 --retry-delay 1 --retry-connrefused -o /dev/null http://127.0.0.1:$PORT/health || exit 1
for USERS in 100 200 400; do
  echo "  ${USERS} users, ${WORKERS} workers..."
  .venv/bin/locust -f locustfile.py --headless -u "$USERS" -r "$((USERS / 5 + 1))" -t 30s \
    --host "http://127.0.0.1:$PORT" --csv "$OUT/u$USERS" --only-summary > "$OUT/u$USERS.log" 2>&1
done
echo "  peak postgres connections during run:"
PGPASSWORD=healthcare /opt/homebrew/opt/postgresql@16/bin/psql -h localhost -p 5433 -U healthcare -d healthcare -tAc "select count(*) from pg_stat_activity where datname='healthcare';"
pkill -f "uvicorn app.main:app --port $PORT" 2>/dev/null
lsof -ti tcp:$PORT | xargs kill -9 2>/dev/null
echo "  done"
