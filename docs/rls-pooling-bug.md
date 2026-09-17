# The leak inside the thing that stops leaks

Row-level security is the second wall in this project. The first is the
application writing `WHERE tenant_id = ...` on every query; the second is
Postgres refusing rows from other clinics whatever the query says.

That second wall has to learn which clinic a request belongs to. It reads a
setting on the database session:

```sql
CREATE POLICY tenant_isolation ON appointments
FOR ALL
USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
```

So every request sets `app.tenant_id` before it queries anything. The obvious
way to do that has a hole in it.

## The hole

`SET app.tenant_id = '...'` attaches the value to the **connection**, and it
stays there until something clears it. Committing does not clear it.

Connections are pooled. When a request finishes, its connection goes back in
the pool and the next request borrows it — along with whatever the last
request left on it.

So:

1. Clinic A's request borrows connection #7 and sets `app.tenant_id` to A.
2. It finishes. Connection #7 returns to the pool, still carrying A.
3. Clinic B's request borrows connection #7.
4. If B's request sets its own value, it overwrites A's and nothing bad
   happens. **If it does not, B runs with A's identity.**

Step 4 is the whole problem. Anything that reaches the database without going
through the normal request path — a background job, a health check, an
endpoint someone adds without the right dependency — inherits whichever clinic
happened to use that connection last. It reads another clinic's patient
records, and every log line says the request succeeded.

It is worse than having no policy at all, because the policy is what convinced
everyone the query did not need checking.

## Why it hides

With a pool of ten connections and two requests, they land on different
connections and nothing is inherited. The bug needs connection *reuse*, which
means it needs either a small pool or enough traffic that connections start
being shared.

That is the wrong way round: it appears under load, in production, and not in
testing.

Forcing it takes one line — a pool of exactly one connection, so the next
request is guaranteed to get the last one back:

```python
create_async_engine(url, pool_size=1, max_overflow=0)
```

## Reproducing it

`tests/test_pooling_leak.py::test_plain_set_leaks_into_the_next_request`

Clinic A's session sets the value with plain `SET` and commits. A second
session on the same connection then reads it back:

```
current_setting('app.tenant_id')  →  <Clinic A's id>
SELECT * FROM users               →  Clinic A's rows
```

No filter removed, nothing sabotaged. A second request simply inherited the
first one's identity.

## The fix

`SET LOCAL` instead of `SET`. It ties the value to the **transaction** rather
than the connection, and the transaction ends at commit or rollback — so the
value is gone before the connection can be handed on, whatever the pool does
with it afterwards.

In this codebase it is `app/database/session.py`:

```python
await db.execute(
    text("SELECT set_config('app.tenant_id', :tenant_id, true)"),
    {"tenant_id": str(tenant_id)},
)
```

`set_config(..., is_local=true)` is the function form of `SET LOCAL`. It is
used instead of the statement form for a second reason: `SET` does not accept
bind parameters, so the statement form means building SQL by string
concatenation — in the one place whose entire job is preventing leaks.

`test_set_local_does_not_leak` and `test_a_rollback_also_clears_it` run the
identical single-connection setup and find the value gone both after a commit
and after a rollback.

## Failing in the safe direction

`current_setting('app.tenant_id', true)` returns NULL when nothing has been
set, and `NULL` compares equal to nothing, so an unset request sees **zero
rows** rather than all of them.

`NULLIF(..., '')` is there because an empty string would reach `''::uuid` and
raise an error instead of matching nothing. Both cases now mean the same
thing: if you did not say which clinic you are, you see nobody.

`test_with_no_clinic_declared_you_see_nothing` covers it.

## One thing deliberately not done

The obvious belt-and-braces addition is resetting the setting when a
connection returns to the pool. SQLAlchemy exposes a `checkin` event for that,
but the handler is synchronous and the connection underneath is asyncpg, so
running a statement there means reaching around the async machinery.

`SET LOCAL` already guarantees the reset at the transaction boundary, and the
tests prove it for both commits and rollbacks. A fragile hook covering a case
that cannot occur would be worth less than this paragraph explaining why it is
absent.

## What to take from it

The mechanism protecting you needs the same suspicion as the code it is
protecting. "We enabled row-level security" and "our clinics are isolated" are
different claims, and the gap between them is one keyword.
