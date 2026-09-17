# Multi-tenant healthcare appointment API

A booking API for clinics, where the hard part is not the booking.

Several clinics share one database. Each one must be unable to reach any
other's patient records — not "should not", but *cannot*, including when the
application code is wrong. Everything below is built around that.

FastAPI · PostgreSQL 16 · Redis · SQLAlchemy 2.0 (async) · Alembic

**135 tests.** Real Postgres and real Redis, never substitutes — half of what
this proves does not exist in a stand-in.

> Not HIPAA-compliant, and not presented as such. It demonstrates the
> multi-tenant isolation patterns healthcare software needs; the compliance
> around them is organisational, not code. See
> [THREAT_MODEL.md](THREAT_MODEL.md).

---

## The idea

A clinic is a tenant. Every user and every appointment belongs to exactly one.
The question the whole design answers is: *how many independent things have to
be wrong before Clinic A sees Clinic B's patients?*

The answer is three.

```
     A request arrives
            │
            ▼
  ┌─────────────────────────────────────────────┐
  │ 1. The clinic comes from a signed token     │
  │    The caller cannot name it themselves.    │
  │    Changing it means forging a signature.   │
  └─────────────────────────────────────────────┘
            │
            ▼
  ┌─────────────────────────────────────────────┐
  │ 2. Every query filters on that clinic       │
  │    Ordinary application scoping.            │
  └─────────────────────────────────────────────┘
            │
            ▼
  ┌─────────────────────────────────────────────┐
  │ 3. Postgres adds the condition itself       │
  │    Row-level security. Holds when the       │
  │    query above is wrong — which is the       │
  │    only case that matters.                  │
  └─────────────────────────────────────────────┘
            │
            ▼
  ┌─────────────────────────────────────────────┐
  │ 4. The schema forbids it outright           │
  │    Composite foreign keys: an appointment   │
  │    cannot pair a patient and a doctor from  │
  │    different clinics. Not even by hand,     │
  │    in psql, as the owner.                   │
  └─────────────────────────────────────────────┘
```

Layers 1 and 2 are really one wall — both depend on the application being
written correctly. Layers 3 and 4 are the ones that hold when it isn't.

## Layout

```
app/
  core/          hashing, tokens, revocation, rate limiting, audit, settings
  database/      models, session, the per-request clinic setting
  dependencies/  who is asking, which clinic, rate limits
  routers/       auth, appointments
  schemas/       what a request may contain, what a reply may expose
alembic/         migrations
scripts/seed.py  two clinics with people in them
tests/           135 tests
docs/            the pooling bug writeup
```

## Running it

Needs Postgres 16 and Redis. Either `docker compose up -d`, or local services
on the same ports.

```bash
git clone <this repo> && cd healthcare-api
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
echo "JWT_SECRET=$(openssl rand -hex 32)" >> .env   # blank on purpose

alembic upgrade head
python -m scripts.seed          # add --reset for a clean slate

uvicorn app.main:app --reload   # docs at /docs
```

`JWT_SECRET` ships empty deliberately. A copied config fails at startup with
instructions rather than quietly running on a signing key that is public on
GitHub.

**Seeded logins** — password `seedpassword123` for all of them:

| Clinic | Email | Role |
|---|---|---|
| `riverside` | `admin@riverside.example.com` | admin |
| `riverside` | `dr.chen@riverside.example.com` | doctor |
| `riverside` | `sarah@example.com` | patient |
| `northgate` | `admin@northgate.example.com` | admin |
| `northgate` | `sarah@example.com` | patient |

Sarah appears twice on purpose. Same address, two clinics, two separate people
with separate records — which is why login needs to know the clinic.

```bash
curl -X POST localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -H 'X-Tenant-Slug: riverside' \
  -d '{"email":"sarah@example.com","password":"seedpassword123"}'
```

Swap `riverside` for `northgate` and the same credentials return a different
person at a different clinic.

## Tests

```bash
pytest                              # 135
pytest tests/test_rls.py            # the isolation floor
pytest tests/test_pooling_leak.py   # the bug worth reading about
```

Every file passes on its own. Tests that borrow setup from whichever test ran
before them pass for reasons unrelated to what they check.

## Three things worth reading the code for

**[The pooling leak](docs/rls-pooling-bug.md).** Row-level security reads the
clinic from a session setting. Set it the ordinary way and it belongs to the
*connection*, not the request — and connections are pooled, so one request's
clinic rides into the next one's. The mechanism preventing leaks becomes the
leak, and every log line says the request succeeded. It only appears when
connections are reused, so it hides in testing and shows up under load.
Reproduced deliberately with a pool of one connection, then fixed with `SET
LOCAL`, and both halves kept as tests.

**Double-booking, proved under real concurrency.**
`tests/test_appointments.py::test_ten_simultaneous_bookings_of_one_slot` fires
ten bookings for the same slot at once and requires exactly one to win. The
rule lives in Postgres as an exclusion constraint over time ranges, because
checking whether a slot is free and then booking it is two steps and two
requests can pass both. The test also asserts all ten were genuinely in flight
at once — without that, ten requests quietly running in sequence would pass
every other line and prove nothing.

**Rate limiting that cannot be raced or straddled.** Counting in application
code means read, add one, write back — twenty simultaneous requests all read
the same number first. The whole decision runs inside Redis as one script.
Counting per clock-minute lets someone spend the full allowance at 11:00:59 and
again at 11:01:00, so the window slides from *now* instead.

## What it does not do

In [THREAT_MODEL.md](THREAT_MODEL.md), stated rather than implied: rate
limiting is per address not per account, there is no encryption at rest, no
account lockout, no tamper-evident audit log, and any signed-in member of a
clinic can book for anyone else in it.
