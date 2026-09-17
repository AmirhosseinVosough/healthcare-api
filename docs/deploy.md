# Deploying this

The app is one container. It needs a Postgres and a Redis it can reach, a
signing key, and three settings got right. None of it is exotic; all of it
bites if skipped.

## Locally, the whole thing at once

```bash
docker compose up --build
# api on http://localhost:8000, docs at /docs
docker compose exec api python -m scripts.seed   # optional demo data
```

Compose starts Postgres and Redis, waits for both to report healthy, then
builds and starts the api. The api's entrypoint runs the migrations and starts
the server. (This machine has no Docker installed, so the compose file is
written but has not been run here — the image build and the entrypoint are
unverified. CI builds the same two service images on first push.)

## On a platform (Fly, Railway, Render, a VM)

Set these, and read the three notes below before you do:

| variable | example | notes |
|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://user:pass@host:5432/db` | must be the `+asyncpg` driver |
| `REDIS_URL` | `redis://host:6379/0` | |
| `JWT_SECRET` | 32+ bytes | from the platform's secret store, never the repo |
| `TRUSTED_PROXY_IPS` | `""` or the proxy's address | see note 1 — the default is safe |
| `WEB_CONCURRENCY` | `1` | see note 2 before raising it |

### Note 1 — the trusted proxy, and how it bites

The per-caller rate limit counts by the caller's address. Behind a platform,
every request reaches the app through the platform's proxy, so the connection
appears to come from the proxy for everyone. The real caller is in the
`X-Forwarded-For` header, which the platform sets.

But a header is written by whoever sends the request. Believe it blindly and an
attacker puts a fresh invented address in it on every guess and never hits the
limit. So the app reads it **only when the connection genuinely came from a
proxy in `TRUSTED_PROXY_IPS`**.

The trap, learned by reproducing it: **only trust an address that outside
clients cannot themselves connect from.** On one machine, where a client and
the proxy are both `127.0.0.1`, trusting `127.0.0.1` trusts the attacker. On a
platform the proxy sits on an internal address unreachable from outside, so
trusting that address is safe. If you cannot find out the proxy's internal
address, leave `TRUSTED_PROXY_IPS` empty: the limit then counts everyone as the
proxy — coarser, but not spoofable.

The container already runs `uvicorn --no-proxy-headers`, so the framework does
not do its own looser version of this before our code is reached.

### Note 2 — pool size times workers, against the database's limit

Each worker keeps its own pool of connections:

```
per worker      pool_size 10 + max_overflow 20   = 30 connections
WEB_CONCURRENCY 4 workers                         = 120 connections
```

Managed databases cap connections, often well below the 100 a local Postgres
allows — some free tiers sit at 20–60. When every worker is busy at once the
total above is what they try to open, and past the cap the extra connections
are refused mid-request. It shows up only under load, which is the worst time
to meet a new error.

**Keep `(pool_size + max_overflow) × WEB_CONCURRENCY` below the database's
connection limit**, with headroom for migrations and any psql or monitoring
sessions. For a 100-connection database and 4 workers, drop the pool: set the
engine to `pool_size=10, max_overflow=5` (60 total). The pool numbers are in
`app/database/session.py`. Not tuned in code because the right values depend on
the database you point it at and how many workers you run.

### Note 3 — migrations on a fleet

The entrypoint runs `alembic upgrade head` on start. For a single container
that is correct and idempotent. For several containers rolling out together,
run the migration once as a separate release step and start the containers
without it, or two of them race to apply the same migration.

## First-run checklist

- [ ] `JWT_SECRET` is 32+ bytes and comes from the secret store. The app
      refuses to start otherwise.
- [ ] `TRUSTED_PROXY_IPS` is empty, or the proxy's *internal* address.
- [ ] `(pool_size + max_overflow) × WEB_CONCURRENCY` < the database's limit.
- [ ] Migrations have run (`alembic current` shows the latest revision).
- [ ] `/health` returns 200; `/docs` loads.
- [ ] A login works, and a sixth rapid attempt returns 429.
