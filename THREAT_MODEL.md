# Threat model

What this API is built to resist, how, and where that is proved. Every claim
below points at a test that runs in CI. Nothing here is aspirational — if a
line stops being true, a test goes red.

**What this is not.** This demonstrates multi-tenant isolation patterns. It is
not HIPAA-compliant and should not be described as such: there is no business
associate agreement, no encryption-at-rest configuration, no key management,
no access-review process, and no retention policy. Those are organisational
controls, and no amount of code supplies them.

---

## 1. One clinic reading another clinic's records

**The risk.** Clinics share one database. A single missing `WHERE tenant_id`
exposes patient records across a tenant boundary, and the query still looks
correct and still returns a 200.

**Three independent walls:**

| Wall | What it does | If it alone failed |
|---|---|---|
| The clinic comes from a signed token | The caller cannot name their own clinic | Attacker picks any clinic |
| Every query filters on it | Normal application-level scoping | One forgotten clause leaks |
| Row-level security in Postgres | The database adds the condition itself | Nothing — this is the floor |

**Why three.** The first two are the same wall in different clothing: both
depend on the application being written correctly. The third holds when the
application is wrong, which is the only case that matters.

**Proved by:**
- `test_rls.py::test_a_query_with_no_where_clause_still_cannot_cross_clinics` —
  `SELECT * FROM users` returns only the caller's clinic.
- `test_rls.py::test_looking_up_another_clinics_appointment_by_id_finds_nothing` —
  the Phase 5 lookup with the application's own filter deliberately removed.
- `test_rls.py::test_with_no_clinic_declared_you_see_nothing` — unset means
  nobody, not everybody.
- `test_appointments.py::test_another_clinic_gets_404_not_403`
- Database-level: composite foreign keys mean an appointment cannot reference
  a patient and a doctor from different clinics at all.

## 2. A stale clinic riding a pooled connection

**The risk.** Row-level security reads the clinic from a session setting. Set
it with plain `SET` and it belongs to the connection, not the request.
Connections are pooled, so one request's clinic is inherited by the next
request to borrow that connection. The mechanism meant to stop leaks becomes
the leak, and every log line reports success.

**Defence.** `SET LOCAL`, which ties the setting to the transaction. It is
discarded at commit or rollback, before the connection can be handed on.

**Proved by:** `test_pooling_leak.py` — the bug is reproduced first with a pool
of one connection, then shown absent with `SET LOCAL`, for both commits and
rollbacks. Full writeup in [docs/rls-pooling-bug.md](docs/rls-pooling-bug.md).

## 3. Confirming a record exists by how it is refused

**The risk.** Answering 403 for another clinic's appointment tells the caller
it exists. Enumerate ids, collect 403s, and you have mapped another clinic's
workload without reading a single record.

**Defence.** 404 everywhere, and the clinic condition sits inside the lookup
rather than in a check afterwards — so there is no moment where the row is in
hand and a check could be skipped.

**Proved by:** `test_appointments.py::test_another_clinic_gets_404_not_403`
asserts the reply for a real appointment at another clinic is byte-identical
to the reply for an id that was never real.

## 4. Mass assignment (over-posting)

**The risk.** If request bodies map onto database models, adding
`"role": "admin"` to a signup grants it, and `"tenant_id": "..."` writes into
another clinic.

**Defence.** Request models are separate and carry only the fields a caller
may set. Role is fixed in code on the registration path. Clinic comes from the
token. Extra keys are dropped before any code sees them.

**Proved by:**
- `test_appointments.py::test_the_clinic_comes_from_the_token_not_the_request`
- Phase 3's registration check: `role` and `tenant_id` sent with a signup,
  account created as a patient in the caller's own clinic.

## 5. JWT algorithm confusion

**The risk.** A token names the algorithm used to sign it. Trust that field
and an attacker sets it to `none`, drops the signature, and writes their own
token naming any clinic and any role.

**Defence.** The algorithm is pinned on our side at decode. The token's own
claim about how to verify it is ignored. Required claims are enforced, and
access and refresh tokens carry distinct types so one cannot stand in for the
other.

**Proved by:** `test_tokens.py` — `alg: none`, a foreign signing key, an edited
signature, a missing `exp`, a missing clinic, an invented role, and a refresh
token used where an access token belongs. Seventeen refusal cases.

## 6. Weak signing key

**The risk.** HS256 with a short secret is guessable, and guessing it means
minting tokens for any clinic. Every other defence here rests on the signature.

**Defence.** The application refuses to start if `JWT_SECRET` is under 32
bytes, naming the command to generate one. `.env.example` ships with it blank
so a copied config fails loudly rather than running on a key published on
GitHub.

**Proved by:** `test_tokens.py::test_signing_key_is_long_enough_for_the_algorithm`
treats PyJWT's key-length warning as an error.

## 7. Password recovery from a stolen database

**The risk.** A leaked table of passwords is reusable everywhere, because
people reuse passwords.

**Defence.** bcrypt at cost 12 — roughly a third of a second per check,
unnoticeable once and ruinous a billion times. Per-password salt, so identical
passwords produce different stored values and cannot be spotted by reading
down the column.

**Proved by:** `test_security.py` — same password hashed twice differs, both
verify, wrong passwords fail, and a corrupt stored hash is a failed login
rather than a crash.

## 8. Silent password truncation

**The risk.** bcrypt ignores everything past 72 bytes without saying so. A
long passphrase is quietly stored as its first 72 bytes, and the user believes
they have more protection than they do.

**Defence.** Over-length passwords are refused rather than truncated, counted
in **bytes** — a line of emoji is 4 bytes per character and would otherwise
slip past a character-count check.

**Proved by:** `test_security.py::test_password_one_byte_too_long_is_refused`
and `test_length_limit_counts_bytes_not_characters`.

## 9. Learning which emails are registered, by timing

**The risk.** If a missing account is refused in microseconds and a real one
takes a third of a second, response time alone reveals who has an account.
Combined with a breach list elsewhere, that is a target list.

**Defence.** The unknown-email path performs the same bcrypt work as a real
check. Wrong password, unknown email and a deactivated account return the same
status, the same body, and the same timing.

**Proved by:** `test_security.py::test_unknown_user_check_costs_the_same_as_a_real_one`
compares best-of-five timings and fails if they diverge.

## 10. Token replay after logging out

**The risk.** A signed token cannot be withdrawn. Logging out of a stateless
system changes nothing on its own — the token keeps working until it expires.

**Defence.** A revocation list in Redis, checked before the database on every
request. Each entry lives exactly as long as the token had left, so the list
clears itself.

**Proved by:** `test_logout.py` — a token that worked a moment ago returns 401
on every protected route after logging out, on one device without touching
others, and without affecting other users.

## 11. A stolen refresh token used for a week

**The risk.** Refresh tokens are long-lived by design. A copy taken from a
backup or a log stays useful for seven days.

**Defence.** Rotation. Using one cancels it and issues a new pair, so a copy
stops working the moment the real holder next refreshes. Logging out cancels
the refresh token too, or logout would be cosmetic.

**Proved by:** `test_refresh.py::test_the_old_refresh_token_stops_working` and
`test_logging_out_kills_the_refresh_token`.

## 12. Brute-forcing passwords

**The risk.** Five guesses a second against a login page is a dictionary
attack. Deliberately slow hashing raises the cost per guess but does not cap
the number of guesses.

**Defence.** Five attempts per caller per minute on login, signup and refresh,
counted as a sliding window so there is no clock boundary to straddle. The
whole decision runs inside Redis as one indivisible step, so simultaneous
requests cannot all read the same count before any writes. Blocked requests
never reach the database or the password hasher.

**Proved by:** `test_rate_limit.py` — the sixth attempt is refused; twenty
simultaneous requests against a limit of five let exactly five through;
spending the allowance and waiting past the halfway point still leaves no room.

## 13. Two patients given the same appointment slot

**The risk.** Checking whether a slot is free and then booking it is two
steps. Two requests can both check, both be told yes, and both book.

**Defence.** The rule lives in Postgres as an exclusion constraint over time
ranges, not in application code. The database serialises the writes; our code
cannot. Cancelled appointments are excluded, so cancelling frees the slot.

**Proved by:** `test_appointments.py::test_ten_simultaneous_bookings_of_one_slot`
— ten requests fired together, exactly one booked, nine refused cleanly, no
crashes. The test also asserts that all ten were genuinely in flight at once,
so it cannot pass by quietly running them in sequence.

## 14. An outage removing a protection

**The risk.** If Redis is unreachable and login proceeds anyway, an outage in
the counting service silently removes brute-force protection from the one page
worth attacking during an outage.

**Defence.** Fail closed, chosen deliberately. Redis unreachable means login is
refused with a 503 and a `Retry-After`. The revocation check does the same: an
unverifiable session is not honoured. An unreachable database is a clean 503,
not a 500, and no reply carries hostnames, ports or usernames.

**The trade-off, stated plainly:** this turns a Redis outage into a login
outage. A brief, visible, understood failure is preferred over silently
unlimited password guessing. For a different product the other choice could be
right — the point is that it is a choice.

**Proved by:** `test_chaos.py` — tested against ports with nothing listening,
not mocks.

## 15. No record of who accessed what

**The risk.** Patient data access that leaves no trail cannot be reviewed
after a suspected breach.

**Defence.** A structured line on every appointment read and write: action,
clinic, user, request id, record id, outcome. Failed lookups are recorded too,
since a run of them from one account is somebody guessing ids. Ids only — a
log that copies the notes has doubled the number of places those notes live.

**Proved by:** `test_audit.py`, including
`test_the_trail_never_copies_the_sensitive_parts`.

---

## Known gaps

Named deliberately. A threat model that lists only what it defends is marketing.

- **Rate limiting is per address.** A clinic behind one office connection
  shares an allowance; an attacker with many addresses gets many allowances.
  Per-account limiting alongside it is the real answer.
- **`X-Forwarded-For` is ignored by default**, which is correct when nothing
  trustworthy sits in front. Deploying behind a proxy means turning that on,
  and turning it on without a trusted proxy lets callers reset their own
  allowance at will.
- **No encryption at rest**, and no key management. A stolen disk is a stolen
  database.
- **No account lockout** after repeated failures, only rate limiting. A patient
  attacker below the limit is not stopped, only slowed.
- **No password strength rules** beyond a minimum length, and no check against
  known-breached passwords.
- **Audit logs go to stdout** with no tamper-evidence. Anyone who can write to
  the log can rewrite history.
- **Any signed-in member of a clinic can book for anyone else in it.**
  Role-based permissions exist in the data model but are not enforced on the
  appointment routes.
- **Tokens are bearer tokens.** Anyone holding one is the holder. There is no
  binding to a device or channel.
