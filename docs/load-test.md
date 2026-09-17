# Load test: finding the ceiling, and moving it

Fifty clinics, 550 users, 2,000 existing appointments. Locust driving a mix
shaped like real traffic — each simulated user logs in once and then works
with the token, because that is what a real client does.

Every number below came off this machine: a 10-core laptop running the API,
Postgres, Redis and the load generator all at once. They are not production
numbers. The *shape* of the curve is the point, not the magnitude.

Rate limiting is off for these runs. All traffic comes from one address, which
is exactly what the limiter exists to refuse, so leaving it on would measure
the limiter rather than the system underneath.

## The baseline, and the collapse

| users | req/s | p50 | p95 | p99 | failures |
|---|---|---|---|---|---|
| 10 | 31 | 8ms | 16ms | 590ms | 0% |
| 25 | 72 | 5ms | 24ms | 1,000ms | 0% |
| 50 | 113 | 4ms | 100ms | 4,200ms | 0% |
| 100 | 117 | 3ms | 4,800ms | 12,000ms | 0% |
| **200** | **8** | 11,000ms | 24,000ms | 26,000ms | 0% |
| 400 | 9 | 7,800ms | 26,000ms | 28,000ms | **49%** |

Throughput climbs to 117 req/s and then falls off a cliff — **117 down to 8**
as concurrency doubles. That is not saturation. A saturated system plateaus.
This one went backwards.

The other oddity: at 100 users the median is 3ms while the 95th percentile is
4,800ms. Almost everything is instant and a few things take five seconds.

## What it actually was

Splitting by endpoint made it obvious:

| | 50 users | 100 users | 200 users |
|---|---|---|---|
| `POST /auth/login` p50 | 3,200ms | 7,800ms | 12,000ms |
| `GET /appointments` p50 | 4ms | 3ms | 9,700ms |
| read requests completed | 2,924 | 3,000 | **70** |

At 200 concurrent users the run completed **217 requests in 30 seconds, 147 of
them logins**. The test never finished logging in.

The cause is not that bcrypt is slow. Bcrypt is slow on purpose, and one login
costing 370ms is the design working. The cause is that it was slow **on the
event loop**.

An async server handles thousands of connections on one thread by never
blocking: every wait hands control back so something else can run. A bcrypt
hash does not wait on anything — it is 370ms of solid arithmetic. Called
directly from a coroutine it does not just make that one request slow, it
stops the worker dead for the duration. Every other request on that process
queues behind somebody else's password.

That explains the 3ms median with a 4,800ms tail exactly. Most requests sail
through; the ones unlucky enough to land behind a hash wait for it.

## The fix

Move the hashing to a worker thread, so the loop stays free:

```python
async def verify_password_async(plain_password: str, password_hash: str) -> bool:
    return await asyncio.to_thread(verify_password, plain_password, password_hash)
```

Nothing about the hashing changed. Same algorithm, same cost factor, same
370ms. It simply stops happening somewhere that blocks everything else.
bcrypt releases the GIL while it runs, so the thread genuinely runs in
parallel rather than only appearing to.

## After

| users | req/s | p50 | p95 | p99 | failures |
|---|---|---|---|---|---|
| 10 | 32 | 6ms | 13ms | 210ms | 0% |
| 25 | 79 | 4ms | 11ms | 230ms | 0% |
| 50 | 155 | 4ms | 20ms | 320ms | 0% |
| 100 | 300 | 3ms | 55ms | 440ms | 0% |
| 200 | **528** | 6ms | 130ms | 1,300ms | 0% |
| 400 | 505 | 210ms | 2,500ms | 5,800ms | 0% |

At 200 users: **8 req/s to 528**. At 100 users the 99th percentile went from
12 seconds to 440ms, and the listing endpoint's 95th from 3,200ms to 40ms.

The curve is now the right shape. It rises, flattens near 200 users, and holds
at 400 instead of collapsing. Failures are zero everywhere, including at 400
where the baseline lost half its requests.

## The next ceiling, and why more workers barely moved it

|  | 100 users | 200 users | 400 users |
|---|---|---|---|
| 1 worker, blocking | 117 req/s | 8 | 9 |
| 1 worker, threaded | 300 | 528 | 505 |
| 4 workers, threaded | 301 | 534 | 608 |

Four processes bought about 20% at the top end and nothing below it, which is
not what more cores should do.

The honest reading is that the measurement is at its own limit. Locust, four
API workers, Postgres and Redis are sharing ten cores, and the load generator
is competing with the thing it is measuring. Past roughly 500 req/s this
setup is measuring the laptop. Finding the real worker-scaling curve needs the
generator on a separate machine.

## Something the four-worker run exposed

Postgres reported 41 connections during it. Not a problem — but the arithmetic
behind it is:

```
pool_size 10 + max_overflow 20  =  30 connections per worker
30 × 4 workers                  =  120
Postgres max_connections        =  100
```

Under load heavy enough for every worker to open every connection, the fourth
one starts being refused. The test never pushed hard enough to reach it, so
this is a hazard found by arithmetic rather than by a failure — which is the
better way to find it.

It also does not announce itself. It appears only when all workers are busy at
once, which is exactly when you least want a new class of error, and the
symptom is a connection failure that looks nothing like "too many workers".

The rule worth carrying: **`(pool_size + max_overflow) × workers` must stay
below the database's connection limit**, with headroom for migrations,
psql sessions and monitoring. For four workers against a 100-connection
database, something like `pool_size=10, max_overflow=5` — 60 total — leaves
room. Not changed here, because the right numbers depend on where it is
deployed and how many workers run.

## Reproducing

```bash
python -m scripts.seed_load --reset       # 50 clinics, 550 users, 2000 appointments
scripts/run_load.sh baseline              # steps through 10 → 400 users
python scripts/load_report.py baseline
```

## What to take from it

The first version was not slow. Up to 100 concurrent users it answered the
median request in 3 milliseconds, and every test in the suite passed. It had a
failure mode that only appears under concurrency, and the thing that broke it
was a security decision working exactly as intended, in the wrong place.

Correctness testing would never have found it. Only load did.
