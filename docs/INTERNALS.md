# Internals — How Every Piece Actually Works

A deep technical walkthrough of this Identity and Access Management platform
(a system that proves who someone is, and decides what they're allowed to
do), written so someone without a background in this area can follow it.

Every abbreviation is spelled out the first time. Every number quoted here
(timeouts, key lengths, retry counts) is the real value from the running
code, not an approximation. Where something is deliberately unfinished, it
says so.

**Companion documents:** `SYSTEM_GUIDE.md` is the simpler, shorter overview —
read that first if you want the shape of the system. This document is the
detailed version: what each service stores, exactly what happens on every
request, and every failure branch.

---

# Part 1 — The Four Kinds of Storage

Before the services make sense, you need to know where data lives. This
system uses four completely different storage systems, each for a specific
reason. Choosing the wrong one for a given piece of data is a real design
error, so each choice below is deliberate.

## 1.1 PostgreSQL — permanent facts

PostgreSQL is a traditional database that writes everything to disk and
guarantees it survives a power cut. It's used for facts that must never be
lost: which companies exist, which users exist, what the rules are.

**Critical rule in this system: one database per service.** There's one
PostgreSQL server running, but it holds five completely separate databases,
and each service can only touch its own:

| Database | Owned by | What's in it |
|---|---|---|
| `tenant_db` | Tenant Service | Companies, and registered third-party apps |
| `identity_db` | Identity Service | Users, their password hashes, their roles |
| `policy_db` | Policy Service | Access rules |
| `device_db` | Device Service | Enrolled phones and their encrypted secrets |
| `audit_db` | Audit Service | The permanent security event history |

Why bother separating them when they're on the same server? Because it makes
one specific mistake *impossible*: a service can never quietly read another
service's tables and start depending on the exact shape of them. If the
Identity Service needs to know whether a company exists, it has to *ask* the
Tenant Service over the network, through a published interface. That means
the Tenant Service can change its internal table layout freely without
silently breaking anyone. This is a well-known pattern called "database per
service," and it's the main thing that keeps independent services actually
independent.

Three services have **no database at all** — the Geo Service (it uses a
read-only lookup file), the Session Service (everything it stores is
short-lived, see below), and the Enforcement Service and OpenID Connect
Provider Service (both only hold temporary state).

### The exact tables

**`tenant_db.tenants`** — one row per company:
```
id          UUID       -- the tenant id everything else references
name        VARCHAR    -- display name, e.g. "Acme Corp"
subdomain   VARCHAR    -- e.g. "acme", used for acme.platform.com
status      VARCHAR    -- ACTIVE / SUSPENDED
created_at  TIMESTAMPTZ
```
`subdomain` has a **unique index** — two companies can never claim the same
subdomain, enforced by the database itself rather than by application code
that might have a race condition between two simultaneous signups.

**`tenant_db.oidc_clients`** — one row per third-party app allowed to use
this platform for login:
```
id                  UUID   -- this is the "client id" the app uses
tenant_id           UUID   -- which company owns this app registration
name                VARCHAR
client_secret_hash  TEXT   -- HASH of the secret, never the secret itself
redirect_uris       TEXT   -- where the app is allowed to be sent back to
created_at          TIMESTAMPTZ
```
Note `client_secret_hash`: when an app is registered, the secret is shown
**once** in the response and then only a hash is stored. Nobody — including
a platform administrator with full database access — can read it back later.
If it's lost, a new one must be issued.

**`identity_db.users`**:
```
id             UUID
tenant_id      UUID
email          VARCHAR
display_name   VARCHAR
status         VARCHAR      -- ACTIVE / SUSPENDED
password_hash  TEXT         -- nullable: a user may exist with no password
role           VARCHAR      -- USER / ADMIN, defaults to USER
created_at     TIMESTAMPTZ
```
Unique index on `(tenant_id, email)` — not on `email` alone. This is
important and deliberate: two *different companies* can each have a user
`admin@example.com`, and they're completely separate people. Email alone is
never an identity in a multi-company system.

**`policy_db.policies`**:
```
id                          UUID
tenant_id                   UUID
scope                       VARCHAR   -- TENANT / OU / USER
scope_id                    UUID      -- which tenant/group/user this applies to
allowed_countries           TEXT      -- nullable
allowed_countries_hard_cap  BOOLEAN
blocked_countries           TEXT      -- nullable
blocked_countries_hard_cap  BOOLEAN
updated_at                  TIMESTAMPTZ
```
Unique index on `(tenant_id, scope, scope_id)` — there can only ever be one
policy row per level per target. The `hard_cap` flags are the mechanism that
lets a company-wide rule refuse to be overridden by a more specific one;
Part 2 walks through exactly how.

**`device_db.devices`**:
```
id                      UUID
tenant_id               UUID
user_id                 UUID
status                  VARCHAR    -- PENDING / ACTIVE
totp_secret_ciphertext  BYTEA      -- ENCRYPTED shared secret
totp_secret_nonce       BYTEA      -- the one-time number used to encrypt it
fcm_token               TEXT       -- nullable, for push notifications
failed_totp_attempts    INT
locked_until            TIMESTAMPTZ -- nullable
created_at, updated_at  TIMESTAMPTZ
```
The phone's secret is stored **encrypted**, not in plain form — see Part 2's
Device Service section for exactly how and why.

**`audit_db.audit_events`**:
```
event_id              UUID PRIMARY KEY
correlation_id        VARCHAR    -- ties together everything from one request
occurred_at           TIMESTAMPTZ -- when the event actually happened
tenant_id             UUID
actor_type            VARCHAR    -- USER / ADMIN / SYSTEM / AGENT
actor_id              VARCHAR
action                VARCHAR    -- e.g. "auth.login_success"
result                VARCHAR    -- SUCCESS / FAILURE / DENIED
reason                TEXT
source_ip, geo, device_id, policy_scope_applied
received_at           TIMESTAMPTZ DEFAULT now()
```
Note there are **two timestamps**: `occurred_at` (when the event really
happened, set by whichever service published it) and `received_at` (when the
Audit Service actually wrote it down). They differ if events are delayed —
which matters a lot when reconstructing a security incident later.

## 1.2 Valkey — short-lived state

Valkey is an in-memory data store (an open-source continuation of a
well-known tool called Redis, after Redis changed its licence in 2024). It
keeps data in fast working memory rather than on disk, which makes it
enormously faster for small reads and writes, at the cost of not being the
right place for data that must survive a total restart.

Every key stored in Valkey here has an automatic expiry — set the value,
tell Valkey "delete this by itself in N seconds." Nothing needs a cleanup
job; expired things simply cease to exist.

Four services use Valkey, each with its own key prefix so they can never
collide (this is the key-value equivalent of "one database per service"):

| Key pattern | Owner | Lives for | What it is |
|---|---|---|---|
| `session:<sha256 of token>` | Session Service | 8 hours | An active login session |
| `session-idem:<tenantId>:<key>` | Session Service | 10 minutes | Duplicate-request protection |
| `push-challenge:<uuid>` | Device Service | 90 seconds | A pending "approve this login?" prompt |
| `oidc:code:<code>` | OpenID Connect Provider | 60 seconds | A one-time login handoff code |
| `oidc:access:<sha256 of token>` | OpenID Connect Provider | 10 minutes | Links an app's token to a real session |
| `policy-cache:<tenant>:<user>:<country>` | Enforcement Service | 30 seconds | A cached policy answer |

## 1.3 Kafka — the event trail

Kafka is a durable log that many programs can write to and many can read
from, without the writer and reader ever needing to be running at the same
moment. Think of a notice board rather than a phone call.

There is exactly **one topic** in normal use — `audit-events` — plus one
safety-net topic, `audit-events-dlq` (dead letter queue: where messages go
when they repeatedly fail to be processed, so they're parked for inspection
rather than lost).

It runs as **three brokers** (three separate copies of the system holding the
data), with every message written to all three and confirmed by at least two
before being considered saved. A single machine dying loses nothing.

## 1.4 OpenBao — secrets, keys and certificates

OpenBao is a secrets manager: an encrypted store for things that must never
appear in source code or configuration files. It fills three separate roles
here:

1. **Key-value secret storage** — the password pepper (explained in Part 2),
   the per-company encryption keys for phone secrets, and the private key
   used to sign login tokens.
2. **A certificate authority** — it issues each service its own digital
   identity certificate at startup, used for service-to-service trust.
3. **An access-control system** — services log in to it with a role
   identifier and secret (called AppRole), rather than everyone sharing one
   all-powerful root token.

**An important operational consequence:** OpenBao stores its data encrypted,
and after any restart it comes back **sealed** — unable to decrypt its own
contents until someone supplies the unseal key. This is not a bug; it's the
entire security guarantee. It means that after restarting the stack, the
bootstrap script must be run again to unseal it, and until that happens every
service that needs a certificate will fail to start. That's correct behaviour
working as designed.

---

# Part 2 — Every Service, In Depth

## 2.1 Tenant Service (`iam-tenant-svc`)

**Job:** own the list of companies, and the list of third-party apps
registered to each company.

**Storage:** `tenant_db` (tables `tenants`, `oidc_clients`).

**What it exposes:**
- `POST /api/v1/tenants` — create a company
- `GET /api/v1/tenants/{id}` — look one up by id
- `GET /api/v1/tenants/by-subdomain/{subdomain}` — look one up by subdomain.
  This exists specifically so the Login Portal can turn
  `acme.platform.com` into a real tenant id.
- `POST /api/v1/oidc-clients` — register a third-party app
- `GET /api/v1/oidc-clients?tenantId=...` — list them (admin only)
- `POST /api/v1/oidc-clients/{id}/verify-secret` — check an app's secret

**The secret verification detail:** the app's secret is hashed on the way in
and only the hash is stored. When the OpenID Connect Provider Service later
needs to check "is this app really who it claims to be," it doesn't fetch the
secret — it *sends* the candidate secret to this endpoint and gets back a
yes/no. The secret never travels back out of this service, in any direction.

**Admin gating:** the list endpoint requires a session token belonging to a
user whose role is `ADMIN` *and* whose session belongs to the same company
being queried. Both checks matter — being an admin of company A must not let
you list company B's apps. This is done by `AdminAccessGuard`, which calls
the Session Service (is this session real?) and the Identity Service (is this
user an admin?) on every such request. It is deliberately **not** shared
library code — authorization logic is business logic, and the shared toolkit
is restricted to purely technical plumbing.

**Notably absent:** there is no "list all tenants" endpoint. Getting a tenant
id requires knowing either the id or the subdomain.

---

## 2.2 Identity Service (`iam-identity-svc`)

**Job:** own users — who exists, their password, their status, their role.

**Storage:** `identity_db.users`.

**What it exposes:**
- `POST /api/v1/users` — create a user
- `GET /api/v1/users/{id}`
- `PATCH /api/v1/users/{id}/status` — activate/suspend
- `PATCH /api/v1/users/{id}/role` — promote/demote
- `PATCH /api/v1/users/{id}/password` — set a password
- `POST /api/v1/users/verify-password` — check a password (internal use)

### How passwords are actually stored

This is worth understanding in detail because it's the most security-critical
code in the system.

A password is never stored. What's stored is an **Argon2id hash** — the
output of a deliberately slow, memory-hungry one-way function. "One-way"
means you can check whether a given password produces the stored value, but
you cannot work backwards from the stored value to the password.

The exact settings used: **memory 19456 kibibytes (about 19 megabytes), 2
iterations, 1 thread, 16-byte salt, 32-byte output.** These are the baseline
numbers recommended by OWASP (a well-known application-security
organisation). The memory cost is the point: an attacker trying billions of
guesses needs 19 megabytes of memory *per simultaneous guess*, which makes
mass cracking with specialised hardware far more expensive.

Each password also gets a **salt** — random data mixed in, stored alongside
the hash — so two users with the same password get completely different
stored values, and an attacker can't precompute a lookup table.

On top of that there's a **pepper**: a single secret value, stored in
OpenBao, appended to every password before hashing. The difference between a
salt and a pepper: the salt is stored next to the hash in the database; the
pepper is not in the database at all. So if someone steals a database dump
but not OpenBao's contents, they cannot even begin to check password
guesses — they're missing an ingredient.

The pepper is fetched lazily on first use and cached in memory, using a
double-checked lock so that many simultaneous requests at startup don't all
fetch it at once. If no pepper exists yet, the first service to look
generates a 32-byte random one and stores it. This "get or create" behaviour
exists so the system works from a cold start with no manual seeding step.

**Known simplification, flagged not hidden:** it's one pepper for the whole
platform, not one per company. The original design called for per-company
peppers via a more advanced OpenBao feature, which needs setup tooling this
build doesn't have yet.

### The user-enumeration defence

`verifyPassword` has a subtle but important property. Look at the three
outcomes:

- Email doesn't exist → returns `{valid: false}`
- Email exists but has no password set → returns `{valid: false}`
- Email exists, password wrong → returns `{valid: false}`

All three are **byte-for-byte identical**. This is deliberate. If "unknown
email" returned a distinguishable answer from "wrong password," anyone could
feed in a list of email addresses and learn which ones have accounts — a real
attack called user enumeration, useful for targeted phishing. The only
successful response carries the user id, status and role.

This endpoint also publishes **no audit event**, which looks like an omission
but isn't: checking a credential is not itself the security decision. The
Authentication Service, which orchestrates the actual login, records the
outcome. Otherwise every login would produce two overlapping records.

---

## 2.3 Geo Service (`iam-geo-svc`)

**Job:** turn an internet address into a country code.

**Storage:** none. It reads a bundled offline database file
(`dbip-country-lite.mmdb`) shipped inside its own container image.

**What it exposes:** `GET /api/v1/resolve?ip=<address>` →
`{ip, resolved, country}`.

**Why no external service call:** this is on the critical path of every
single login *and* every subsequent request. Calling an external geolocation
service over the internet would add unpredictable latency and create a
dependency on a third party being up. An offline file lookup is
sub-millisecond and can't fail for network reasons.

**Internal behaviour, step by step:**
1. The address is checked against a strict pattern for four dot-separated
   numbers. Anything else is rejected immediately as invalid — including
   IPv6 addresses, which this MVP doesn't handle.
2. **Local-development-only special case:** if the address is a private
   network address (the `172.x`, `10.x`, `192.168.x` ranges used inside
   Docker and office networks), it returns `US` as a hard-coded answer.
   This exists purely because in local testing every request arrives from
   Docker's internal gateway address, which no real geolocation database
   contains — so without this, every local login would be denied as
   "location could not be verified." **In a real deployment behind a proper
   ingress seeing real public addresses, this branch never runs.** It's
   flagged clearly in the code as a local fixture, not a real geographic
   claim.
3. Otherwise it looks the address up in the bundled database and returns the
   country code.
4. If the address is valid but the database has no entry, it returns
   `resolved: false` with no country. **This is not an error** — it's a
   legitimate answer meaning "I genuinely don't know," and every caller
   treats "don't know" as a denial rather than a pass.

---

## 2.4 Policy Service (`iam-policy-svc`)

**Job:** store the access rules, and answer the question "is this user, from
this country, allowed?"

**Storage:** `policy_db.policies`.

**What it exposes:**
- `PUT /api/v1/policies` — create or replace a policy at a given level
- `GET /api/v1/policies?...` — read one back
- `POST /api/v1/evaluate` — the actual decision endpoint

### The merge algorithm, in full

This is the most intricate logic in the system, so it's worth going slowly.

Rules can be set at three levels of specificity:
- **TENANT** — applies to the whole company
- **OU** — applies to an organisational unit (a department or group)
- **USER** — applies to one specific person

And there are two independent attributes:
- **allowedCountries** — a positive list: if set, *only* these countries pass
- **blockedCountries** — a negative list: these countries never pass

The naive approach would be "the most specific level completely replaces the
broader one." That's wrong for a real organisation, because it means setting
any user-level rule silently discards every company-level rule for that
person. So instead this system **merges per attribute**:

> For each attribute independently, the most specific level that actually
> *sets* that attribute wins. A level that leaves an attribute unset does not
> override it — it inherits from the next broader level.

Concretely, `resolveAttribute` runs this exact sequence for each attribute:

1. **If the TENANT level marks this attribute as a hard cap and has a value
   for it → the tenant value wins, immediately, unconditionally.** No
   OU-level or user-level value for that attribute is even consulted. This is
   the mechanism that lets a security team set a rule nobody downstream can
   loosen.
2. Otherwise, if the USER level sets it → use that.
3. Otherwise, if the OU level sets it → use that.
4. Otherwise, if the TENANT level sets it → use that.
5. Otherwise → the attribute is undefined, meaning unconstrained.

**A worked example.** Company-wide: `blockedCountries = [KP, IR]` marked as a
hard cap; `allowedCountries = [IN, US]` not a hard cap. One particular user
has `allowedCountries = [IN, US, GB]` and no blocked list.

- Resolving `blockedCountries`: tenant hard cap is set → **`[KP, IR]` wins**.
  The user's (absent) value is irrelevant; even if the user level had tried
  to set an empty block list, it would be ignored.
- Resolving `allowedCountries`: tenant is not a hard cap, and the user level
  *does* set a value → **`[IN, US, GB]` wins**.

So this user can log in from Great Britain (their own wider allow-list
applies) but still not from Iran (the hard cap holds). Two attributes,
resolved independently, at two different levels. That's the merge.

### The evaluation order

Once both attributes are resolved, the check runs in a specific order:

1. **Blocked list first.** If the country is in the resolved blocked list →
   denied, with reason `country 'XX' is in blockedCountries`. An explicit
   block always beats an allow.
2. **Then the allowed list.** If a resolved allowed list exists *and* the
   country isn't in it → denied, reason `country 'XX' is not in
   allowedCountries`.
3. Otherwise → allowed.

Note the asymmetry in step 2: if no allow-list is defined anywhere, that
means "no country restriction," not "nothing is allowed." But *if* one is
defined, it's a strict allow-list — being absent from it is a denial, not
merely "not explicitly blocked."

The answer also carries `policyScopeApplied` — which level produced the
decision (`TENANT`, `OU` or `USER`). This ends up in the audit record, so
months later you can tell not just that someone was denied but *which rule
did it*.

**Design note:** the evaluator is a pure function with no database or
framework dependencies — it takes three policy records and a country and
returns an answer. That's why it can be tested exhaustively without starting
any infrastructure, which matters for the piece of code that decides who gets
in.

---

## 2.5 Session Service (`iam-session-svc`)

**Job:** issue, validate and destroy login sessions.

**Storage:** Valkey only. No PostgreSQL. A session is by definition temporary
and re-creatable by logging in again; the permanent record of "a login
happened" lives in the audit log instead.

**What it exposes:**
- `POST /api/v1/sessions` — issue a session
- `GET /api/v1/sessions` (token in the `X-Session-Token` header) — validate
- `DELETE /api/v1/sessions?reason=...` — terminate

### The token

A session token is **32 bytes from a cryptographically secure random number
generator**, encoded as base64url without padding — 43 characters. 32 bytes
is 256 bits of randomness, which is far beyond guessable: there is no
practical way to find a valid token by trying values.

**It is deliberately not a JSON Web Token.** A JSON Web Token (JWT) is a
self-describing signed token that any service can verify offline without
asking anyone. That sounds better, and for many systems it is — but it has
one fatal property for this platform: **you cannot revoke it.** Once issued,
it stays valid until it expires, because verification doesn't involve any
central lookup. This system's entire AP-2 principle is "a session must be
killable mid-flight," so it uses an opaque random token that means nothing by
itself and must be looked up centrally every time. Killing a session is then
just deleting one key.

### How it's stored

The token is **not** the Valkey key. The key is `session:` followed by the
**SHA-256 hash** of the token. The stored value is the session record —
session id, tenant id, user id, source address, device id, issued-at,
expires-at — and it notably **never contains the token itself**.

Why hash it? If someone obtained a dump of the Valkey keyspace, they'd get a
list of hashes, which are useless as credentials — you can't present a hash
to log in. Without this, a memory dump would hand over every live session as
a ready-to-use bearer token.

Note this is a plain SHA-256 with no salt or stretching, unlike passwords.
That's correct here, not a shortcut: the input is already 256 bits of pure
randomness, so there's no dictionary to attack and nothing to slow down.

Default session lifetime: **8 hours**, applied as a Valkey expiry so the
session deletes itself.

### Duplicate-request protection (idempotency)

Consider this failure: the Authentication Service asks for a session, the
session is created, and then the network drops the response. The
Authentication Service retries. Without protection, you'd now have two live
sessions for one login.

The fix: the caller passes an idempotency key (the request's correlation id).
Before issuing anything, the Session Service runs an **atomic "set if
absent"** on `session-idem:<tenantId>:<key>` with a 10-minute window. Two
things matter about this:

- It's **atomic** — the check and the claim are one indivisible operation, so
  two genuinely simultaneous retries can't both see "not claimed yet" and
  both proceed.
- The claim happens **before** issuing, not after. If it happened after,
  there'd be a window between issuing and claiming where a retry could slip
  through.

If the claim fails, the request is a retry, so it **replays**: it looks up
the originally issued token and returns that same session. Before returning
it, it verifies the original session was for the same tenant and user — if
someone reuses an idempotency key for a *different* request, that's a
conflict error, not a silent wrong answer.

### Termination

Termination uses Valkey's **GETDEL** — fetch the value and delete it as one
atomic operation. The reason is the same class of problem as above: if it
were a separate "read, then delete," two simultaneous termination requests
could both read the session successfully and both publish a
`session.terminated` audit event for one session. With GETDEL exactly one of
them gets the value; the other finds nothing and correctly reports "not
found."

Terminating a non-existent session raises `SessionNotFoundException` rather
than silently succeeding — callers should be able to tell the difference.

---

## 2.6 Device Service (`iam-device-svc`)

**Job:** the second security factor — the rotating six-digit code, and the
"approve this login?" push notification.

**Storage:** `device_db.devices` for enrolment, Valkey for in-flight push
prompts.

**What it exposes:**
- `POST /api/v1/devices/enroll`
- `POST /api/v1/devices/totp/verify`
- `POST /api/v1/devices/push/send`
- `POST /api/v1/devices/push/respond`

### Enrolment and the shared secret

The rotating code system (called TOTP — Time-based One-Time Password) works
by the server and the phone sharing one secret value, then both independently
computing a code from `(secret, current time)`. No messages are exchanged at
code-generation time, which is why it works with the phone offline.

On enrolment:
1. Verify the user exists and belongs to the claimed company — **if the user
   id exists but belongs to a different tenant, this is rejected exactly like
   a nonexistent user.** Otherwise the tenant id would be a meaningless
   parameter you could pass anything into.
2. Generate **20 random bytes** as the shared secret.
3. Encrypt it (see below).
4. Save the row with status `PENDING`.
5. Return the secret in Base32 form plus an `otpauth://` provisioning link,
   which is what a QR code encodes for authenticator apps.

The device starts `PENDING` and only becomes `ACTIVE` when the user
successfully verifies a code for the first time — proving the secret actually
made it onto the phone rather than the QR scan having silently failed.

### How the secret is encrypted

The shared secret is as sensitive as a password: anyone holding it can
generate valid codes forever. So it's never stored in readable form.

It's encrypted with **AES-256 in Galois/Counter Mode** — a standard
encryption method that provides both confidentiality (unreadable without the
key) and integrity (tampering is detectable). Specifically:
- A fresh **12-byte nonce** ("number used once") per encryption, random each
  time. Reusing a nonce with the same key in this mode is catastrophic, so it
  is generated fresh for every single encryption and stored in its own
  column.
- A **128-bit authentication tag**, which means a modified ciphertext fails
  to decrypt rather than silently producing garbage.
- The key is a **per-company data encryption key** fetched from OpenBao. One
  company's stolen key cannot decrypt another company's device secrets.

So the database holds ciphertext plus nonce; the key lives in OpenBao. A
database dump alone yields nothing usable.

### Verifying a code

1. Fetch the most recent device for this tenant and user. (The index is on
   `(tenant_id, user_id, created_at DESC)` for exactly this lookup;
   re-enrolling creates a new row and the newest wins.)
2. **Lockout check first** — if `locked_until` is set and still in the
   future, return immediately with status `LOCKED`, without even attempting
   to check the code. Checking first would let an attacker keep testing codes
   during a lockout.
3. Decrypt the secret, compute the expected code, compare.
4. **Drift window:** codes change every 30 seconds, and the phone's clock is
   never perfectly aligned with the server's. So the check accepts the code
   for the current 30-second step *and* one step either side — a tolerance of
   ±30 seconds. This is a genuine security/usability trade-off: a wider
   window is friendlier to clock drift but leaves each code valid longer.
   One step is the standard choice.
5. **On success:** reset the failure counter, clear any lock, promote
   `PENDING` → `ACTIVE`, save.
6. **On failure:** increment the counter. At **5 failures**, set
   `locked_until` to 5 minutes ahead and publish a `device.locked` audit
   event. Below 5, just record the failed attempt.

The counter resets on *any* success, so five scattered typos over a week
never accumulate into a lock.

### Push notifications

1. Find the most recent device that has a push token — **if the user has a
   device but it has no push token, that's a distinct error**
   (`NoPushCapableDeviceException`), not "no device."
2. Create a challenge in Valkey: `push-challenge:<uuid>`, status `PENDING`,
   **90-second expiry**.
3. Send the notification via Firebase Cloud Messaging.
4. **If sending fails, delete the challenge immediately** and raise the
   error. Leaving an orphaned challenge would mean a prompt nobody will ever
   answer sitting there for 90 seconds.
5. Wait for resolution by **polling Valkey once per second** for up to **60
   seconds**.
6. Meanwhile, when the user taps Approve or Deny on their phone, the app
   calls `push/respond`, which flips the challenge status.
7. Outcome: `APPROVED`, `DENIED`, or `TIMEOUT`. On timeout, the challenge is
   deleted and a `device.push_timeout` audit event is published.

Note the two different durations: the challenge lives **90** seconds in
Valkey but the server only waits **60**. The gap is deliberate — it means a
response arriving slightly after the server gave up still finds a valid
challenge to write to rather than a confusing "challenge not found" error on
the user's phone.

`push/respond` also rejects any challenge that isn't still `PENDING`
(`ChallengeAlreadyResolvedException`) — you can't approve something twice, or
approve something already denied.

**Honest note on the polling design:** blocking a request thread for up to 60
seconds while polling once a second is not how a high-scale system would do
this — it ties up a thread per pending login. A production version would use
an event-driven wait. It's simple, correct, and adequate at MVP scale.

---

## 2.7 Authentication Service (`iam-auth-svc`)

**Job:** the login orchestrator. The single place where a login decision is
made.

**Storage:** none. It owns no data; it coordinates other services.

**What it exposes:** `POST /api/v1/login`, `POST /api/v1/logout`.

This service exists to enforce architectural principle AP-1: *one auth
engine, not five.* There must be exactly one code path that decides "yes,
issue a session," so that no future feature can accidentally create a second
route in that skips a check. No other service is permitted to issue a
session.

### The exact login sequence

Order matters here, and the specific order chosen has real consequences:

**Step 1 — Verify the password.** Calls the Identity Service. If invalid →
publish `auth.login_failure` (result `FAILURE`, reason "invalid credentials")
and return 401.

**Step 2 — Check account status.** If the user is not `ACTIVE` → publish
`auth.login_denied` (`DENIED`, "account suspended") and return 403 with error
code `ACCOUNT_SUSPENDED`. Note this is checked *after* the password: a
suspended user who types the wrong password gets "invalid credentials," not
"this account is suspended," so suspension status isn't leaked to someone who
can't authenticate.

**Step 3 — Resolve location.** Calls the Geo Service. Crucially, this call is
wrapped so that a circuit-breaker rejection or a network failure returns
`null` rather than propagating. That converts an infrastructure problem into
a *denial*, not a 503 error — "never fail open."

**Step 4 — Evaluate policy.** If the country couldn't be resolved, the
decision is already "denied: location could not be verified" and the Policy
Service isn't even called. Otherwise, evaluate. Again wrapped: if the Policy
Service is unreachable, the decision is "denied: policy could not be
evaluated."

If denied, the reason is mapped to a specific error code so the login page
can show accurate wording:
| Reason | Error code |
|---|---|
| location could not be verified | `LOCATION_UNVERIFIED` |
| policy could not be evaluated | `POLICY_UNAVAILABLE` |
| anything else | `POLICY_DENIED` |

**Step 5 — Second factor.** Only reached if policy passed. Two branches:
- **A six-digit code was supplied** → verify it with the Device Service.
  Outcomes: valid → continue; device locked → `TOTP_LOCKED`; otherwise
  `TOTP_INVALID`. A "not found" response means no second factor is enrolled
  (`NO_SECOND_FACTOR_ENROLLED`). A circuit-breaker or network failure gives
  `SECOND_FACTOR_UNAVAILABLE` — again a denial, never a bypass.
- **No code supplied** → fall back to a push notification and block until
  the user answers. Outcomes map to `PUSH_DENIED`, `PUSH_TIMEOUT`, or
  `NO_PUSH_DEVICE_ENROLLED`.

**Why is the second factor checked *after* the policy check?** Because if
someone is going to be denied for being in a blocked country anyway, there's
no reason to wake their phone up with a push notification first. It also
means a blocked-location attempt never produces a push prompt that might
confuse or alarm the real user.

**Step 6 — Issue the session.** Calls the Session Service, passing the
correlation id as the idempotency key. This call is deliberately **not**
wrapped in the failure-to-denial helper: if session issuance fails, that
propagates as a 503. The distinction is meaningful — "we couldn't verify you,
so no" (a denial) versus "we verified you fine but our own machinery broke"
(an error). Conflating them would hide real outages behind what looks like a
policy decision.

**Step 7 — Publish `auth.login_success`** and return the token, session id,
expiry, and the user's role.

Note that **every single denial branch publishes an audit event before
throwing**, so there is no way to fail a login without leaving a record.

---

## 2.8 Enforcement Service (`iam-enforcement-svc`)

**Job:** continuous, per-request enforcement — AP-2. Plus, now, acting as the
gateway that real applications sit behind.

**Storage:** Valkey, for a short policy-decision cache only.

**What it exposes:**
- `POST /api/v1/enforce` — the original check endpoint
- `/proxy/**` — the reverse proxy front door
- `GET /oauth2/callback` — where login returns to
- `GET /oauth2/logout`

### The core check

Given a session token and the request's current source address:

1. **Validate the session** with the Session Service. Not found, expired, or
   terminated → denied. **This is never cached** — caching session validity
   would defeat the entire purpose, since the whole point is noticing a
   session that was killed a second ago.
2. **Resolve the current location.** Note: *current*, not the address
   recorded at login. That's the essence of continuous enforcement — asking
   where the request is coming from *now*. The session's original address is
   only ever metadata.
3. **Evaluate policy** — with a short cache (below).
4. **If denied:** terminate the session via the Session Service, publish
   `enforcement.violation`, and return 401. The session is gone platform-wide
   from that moment, not just for this one request.

### The cache, and its exact key

Policy decisions are cached for **30 seconds** at
`policy-cache:<tenantId>:<userId>:<country>`.

The key includes the **user id**, not just tenant and country. This was
corrected during implementation and it matters: a tenant-and-country-only key
would return one user's decision for a different user — and since policy
supports per-user overrides, two users in the same company and country can
legitimately get different answers. A coarser key would silently apply the
wrong person's rules.

### The three denial reasons are treated differently

| Situation | Session killed? | Audit action |
|---|---|---|
| Session unknown/expired/terminated | No (nothing to kill) | **No audit event at all** |
| Location couldn't be resolved | No | `enforcement.check_denied` |
| Policy service unreachable | No | `enforcement.check_denied` |
| Policy actively says no | **Yes** | `enforcement.violation` |

The first row deserves explanation: when a token doesn't resolve to anything,
there is no tenant id or user id to attribute an audit record to. Rather than
fabricating a record around an identity that was never established, it
publishes nothing. All four cases return the same `401` to the caller.

The distinction between rows 2–3 and row 4 is equally deliberate: an
inconclusive check (we couldn't reach the geolocation service) denies *this
request* but leaves the session alone, because the user did nothing wrong and
the situation may be transient. Only a confirmed policy violation destroys
the session.

### The gateway

The proxy accepts two ways of proving identity, tried in order:

**Path A — `X-Session-Token` header.** For direct, programmatic callers that
already hold a real session token. Runs the core check above.

**Path B — a gateway cookie.** For ordinary web browsers. This is what lets a
normal application sit behind the gateway:

1. **No header and no cookie** → the gateway redirects the browser to the
   platform's own login, acting as a standard OpenID Connect client. The
   originally requested path is base64-encoded into the `state` parameter so
   it can be returned to afterwards.
2. After login, the browser lands on `/oauth2/callback` with a one-time
   code, which the gateway exchanges for an access token.
3. The gateway sets a cookie: **`HttpOnly`** (JavaScript cannot read it,
   defeating cross-site-scripting theft), **`SameSite=Lax`** (not sent on
   cross-site requests, defeating cross-site request forgery, while still
   surviving the top-level redirect back from the login page), `Secure` when
   configured for real HTTPS, and a `Max-Age` matching the token's own
   lifetime.
4. On every later request, the cookie's token is checked for liveness via the
   Provider Service's `/userinfo` — which itself re-checks the underlying
   session is still alive — and then the same location-and-policy re-check
   runs.
5. **On denial:** if it's a genuine policy violation, terminate the
   underlying session, clear the cookie, return 401. If it's an inconclusive
   failure, deny the request but leave the session alone — the same
   distinction as above.
6. **If the cookie's token is dead** (expired, or the session was killed
   elsewhere), the cookie is cleared and the browser is sent back to login —
   not shown an error.

**Open-redirect protection:** the `state` value round-trips through the
browser, so it's attacker-influencable. On the way back, the decoded path is
only honoured if it starts with `/proxy` — otherwise it falls back to a safe
default. Without this, someone could craft a link that authenticates a victim
and then bounces them to a hostile site.

### What the upstream application receives

Before forwarding, the gateway:
- **Strips** the `Host` header (stale, would confuse the upstream's routing),
  the `X-Session-Token` header (the app has no business seeing platform
  credentials), the whole `Cookie` header for cookie-authenticated callers,
  and **any incoming `X-Auth-*` header**.
- **Then adds** its own: `X-Auth-User-Id`, `X-Auth-Tenant-Id`, and (on the
  cookie path, where it's available for free) `X-Auth-User-Email`.

The stripping of incoming `X-Auth-*` headers is the security-critical half.
Without it, any caller could set `X-Auth-User-Id: <victim>` and the
application behind the gateway — which trusts those headers by design — would
believe them. The header is only meaningful because the gateway guarantees
it's the only possible source.

**Asymmetry worth knowing:** the email header only appears on the cookie
path, because that path already fetches user details for liveness. The header
path never had a source for email and adding one would mean a new dependency
just for that field.

---

## 2.9 OpenID Connect Provider Service (`iam-oidcprovider-svc`)

**Job:** let other applications use this platform for login, using the
industry-standard OpenID Connect protocol (built on OAuth 2.0).

**Storage:** Valkey only — short-lived codes and token links. Everything
durable is read from the Tenant, Identity and Session Services.

**What it exposes:** `/authorize`, `/token`, `/userinfo`, `/jwks.json`,
`/.well-known/openid-configuration`, plus the internal
`/authorize/complete` and `/internal/access-tokens/terminate`.

### The flow, step by step

1. **`GET /authorize`** — the app sends the browser here. The service
   validates the `client_id` exists and, critically, that the supplied
   `redirect_uri` is **exactly one of the ones registered for that client**.
   If either check fails it renders an error page and **redirects nowhere**.
   That's a deliberate security rule: redirecting an invalid request to an
   unvalidated address is exactly how tokens get stolen.
2. Valid requests are redirected to the Login Portal — this service never
   handles a password itself.
3. **`POST /authorize/complete`** — after the portal has authenticated the
   user against the Authentication Service, it calls here server-to-server
   with the resulting session token. This re-validates the client and
   redirect address *again* (defence in depth — it doesn't assume the earlier
   check still applies to this request), confirms the session is real, and
   confirms **the session's tenant matches the client's tenant** — company A's
   user cannot obtain a token for company B's app.
4. It then mints an **authorization code**: 32 random bytes, stored at
   `oidc:code:<code>` for **60 seconds**, holding the client id, tenant, user,
   email, redirect address, scope, and the session token.
5. **`POST /token`** — the app exchanges the code. The code is redeemed with
   **GETDEL**, so it is strictly single-use: a stolen code that's already been
   used is worthless. It then checks the code was issued to this same client
   and redirect address, and verifies the client secret.
6. Two signed tokens are returned: an **ID token** (who the user is) and an
   **access token** (permission to call `/userinfo`), both signed with an RSA
   key held in OpenBao, both valid **10 minutes**.

### The access-token link — and why it exists

Here's the subtle part. The platform's real session token is powerful — it
works against every service in the system. A third-party application must
never receive it.

But `/userinfo` needs to be able to tell whether the underlying session is
still alive, so that killing a session immediately invalidates the app's
token too.

The solution: `AccessTokenLinkStore` keeps `oidc:access:<sha256 of access
token>` → the real session token, in Valkey, for the access token's lifetime.
When `/userinfo` is called, the service looks up the session token
**internally**, checks liveness, and returns only the user's details. The raw
session token never leaves the service in any response.

This is what makes the AP-2 guarantee reach all the way into third-party
apps: the Enforcement Service kills a session → the link lookup still finds
the session token → the liveness check fails → the app's access token stops
working immediately, rather than remaining valid until its own expiry.

### The internal termination endpoint

`POST /internal/access-tokens/terminate` was added for the gateway. It takes
an access token, resolves it to the session token server-side, and terminates
that session — **without ever returning the session token to the caller.**
This preserves the boundary above while still letting the gateway enforce a
policy violation on a cookie-authenticated user. It returns `false` rather
than an error if the token is already unknown, since terminating something
already gone is a no-op, not a failure.

---

## 2.10 Audit Service (`iam-audit-svc`)

**Job:** consume every audit event from Kafka and store it permanently.

**Storage:** `audit_db.audit_events`.

**It has no inbound API and makes no outbound calls to any other service.**
That's what made it safe to build first — it depends on nothing.

### How consumption works

1. Read a message from the `audit-events` topic.
2. Parse it.
3. **Check whether this event id already exists.** If so, log and skip.
4. Otherwise save.

Step 3 is the idempotency guard. Kafka guarantees at-least-once delivery, not
exactly-once — the same message genuinely can arrive twice (for example if
the consumer crashes after saving but before recording its progress). Without
this check, the audit log would contain duplicates, which is corrupting for a
security record.

### When processing fails

Handled by a `DefaultErrorHandler` with **exponential backoff**: first retry
after 1 second, doubling each time, capped at 30 seconds between attempts,
for a configurable maximum (default 5) attempts. If it still fails, the
message is published to **`audit-events-dlq`**.

The dead-letter topic is a real, explicitly named topic — not an
auto-generated one — so a failed audit event is parked somewhere inspectable
rather than dropped. For a security audit trail, silently losing an event is
the single worst possible failure, so there is no code path that does it.

### On the publishing side

Every service publishes through one shared `KafkaAuditPublisher`, never
touching Kafka directly. It:
- Serialises the event to JSON.
- Sets the Kafka message **key to the tenant id** — which means all events
  for one company land on the same partition and are therefore strictly
  ordered relative to each other. Cross-company ordering doesn't matter;
  within-company ordering does when reconstructing an incident.
- Puts the correlation id both in the payload **and** as a message header.
- Sends **asynchronously** — the caller does not wait. This is the whole
  reason Kafka is here: recording history must never slow down or block the
  actual security decision.
- If the send ultimately fails after the producer's own retries, it **logs an
  error locally** with the event id, action and correlation id. Not silent.

Producers are configured with `acks: all`, meaning a write isn't acknowledged
until it has reached the required number of replicas — not just the one
leading broker.

---

## 2.11 The Shared Toolkit (`iam-service-kit`)

Not a running service — a library every backend service includes. It is
strictly limited to **technical plumbing**; it is forbidden from containing
domain concepts like `User`, `Policy` or `Session`. Each service defines its
own versions of those from the published interface it talks to. The
duplication is intentional: it's the price of services being able to change
independently.

What's in it:

**Correlation ID handling.** A filter registered at the highest precedence,
so it runs before everything else. Every inbound request either carries an
`X-Correlation-Id` header or gets a newly generated one. It's placed in the
logging context (so every log line from that request carries it), echoed back
on the response, and made available for outbound calls and audit events.
Crucially it's cleared in a `finally` block — because threads are reused
between requests, and a leftover correlation id would silently mislabel the
next request's logs.

**The resilient HTTP client.** Every outbound call between services goes
through this, never a bare client. It provides:
- **Timeouts** — 2 seconds to connect, 5 seconds to read. No call may wait
  indefinitely.
- **Retry** — up to 5 attempts with exponentially increasing delays.
- **Circuit breaker** — tracks a sliding window of 5 calls; once at least 5
  calls have been made and more than 50% failed, it "opens" and immediately
  rejects further calls for 30 seconds before cautiously trying again. This
  stops a struggling service from being buried under retries.
- **Automatic mutual-TLS** — presents this service's certificate on every
  outbound call if one was provisioned at startup, and is a silent no-op
  otherwise.

**An important subtlety in the configuration:** expected business outcomes
must be excluded from both the retry and the circuit breaker. A `404 Not
Found` when checking a session simply means "no such session" — it is not a
failure. If it weren't excluded, normal operation would trip the circuit
breaker and take down a healthy service. This was the cause of a real bug
found during development: a legitimate `401` from `/userinfo` wasn't excluded
for a newly added client, so five rapid retries against an expired token
tripped the breaker mid-request and surfaced a misleading 503.

**The OpenBao client** for reading and writing secrets.

**The audit publisher**, described above.

---

## 2.12 The Two Web Front-Ends

**Login Portal** (Next.js, server-rendered) — the branded page users actually
type into. It resolves which company a visitor belongs to from the subdomain
(or, in local development where there's no wildcard DNS, from a `?tenant=`
query parameter). It calls the Authentication Service directly, and in the
third-party-login flow it hands the resulting session token to the OpenID
Connect Provider's `/authorize/complete` **server-to-server** — the raw token
is never exposed to the browser's JavaScript in that flow.

**Admin Console** (React with Vite, served by nginx) — the tenant
administrator's interface for users, policies and audit history. Every
admin-gated call it makes is independently re-checked for the `ADMIN` role by
the receiving service. The role returned at login is a **UI convenience
only** — it decides which buttons to render, and is never trusted as
authorization. Anyone can send any request; the backend decides.

---

# Part 3 — A Complete Login, Traced Hop by Hop

Every network call and storage touch for one successful login with a
six-digit code.

```
Browser                  → Login Portal      : POST credentials
Login Portal             → Tenant Service    : GET /tenants/by-subdomain/acme
                                               → reads tenant_db
Login Portal             → Auth Service      : POST /api/v1/login
                                               [correlation id generated here]

  Auth Service           → Identity Service  : POST /users/verify-password  (mutual TLS)
                                               → reads identity_db
                                               → fetches pepper from OpenBao (first time only)
                                               → Argon2id comparison
                                               ← {valid, userId, status, role}

  Auth Service           → Geo Service       : GET /resolve?ip=...  (mutual TLS)
                                               → offline database lookup
                                               ← {resolved: true, country: "US"}

  Auth Service           → Policy Service    : POST /evaluate
                                               → reads policy_db (up to 3 rows)
                                               → merge-with-hard-cap resolution
                                               ← {allowed: true, policyScopeApplied}

  Auth Service           → Device Service    : POST /devices/totp/verify  (mutual TLS)
                                               → reads device_db
                                               → fetches per-tenant key from OpenBao
                                               → AES-256-GCM decrypt, compute, compare ±30s
                                               → resets failure counter, PENDING → ACTIVE
                                               → publishes device.totp_verified → Kafka
                                               ← {valid: true}

  Auth Service           → Session Service   : POST /sessions  (mutual TLS)
                                               → atomic claim on session-idem:<tenant>:<corrId>
                                               → generates 32 random bytes
                                               → writes session:<sha256> to Valkey, 8h expiry
                                               → publishes session.issued → Kafka
                                               ← {token, sessionId, expiresAt}

  Auth Service           → Kafka             : auth.login_success
                                               ← returns to portal
```

Meanwhile, entirely asynchronously:
```
Kafka (3 brokers, replicated) → Audit Service : consumes each event
                                                → duplicate check by event id
                                                → writes to audit_db
```

Every one of those events carries the **same correlation id**, so one
database query against `audit_db` reconstructs the entire login across six
services.

If the app being logged into is a third-party one, three more hops follow:
```
Login Portal  → OIDC Provider : POST /authorize/complete (server-to-server)
                                → validates client + redirect + session tenant match
                                → writes oidc:code:<code> to Valkey, 60s expiry
                                ← redirect URL containing the code
Browser       → the app        : lands with ?code=...
The app       → OIDC Provider : POST /token
                                → GETDEL the code (single use)
                                → verifies client secret via Tenant Service
                                → signs ID + access tokens with the OpenBao key
                                → writes oidc:access:<sha256> → session token
                                → publishes oidc.token_issued → Kafka
                                ← {access_token, id_token}
```

---

# Part 4 — Continuous Enforcement, Traced

Later, mid-session, the user's location changes to a blocked country:

```
Request  → Enforcement Service : /proxy/... or POST /api/v1/enforce

  → Session Service : GET /sessions  (never cached)
                      → reads session:<sha256> from Valkey
                      ← session record (still valid)

  → Geo Service     : GET /resolve?ip=<CURRENT address>
                      ← {country: "KP"}

  → checks policy-cache:<tenant>:<user>:KP  → miss (different country key)
  → Policy Service  : POST /evaluate
                      ← {allowed: false, reason: "country 'KP' is in blockedCountries"}

  → Session Service : DELETE /sessions   → GETDEL removes the key
                      → publishes session.terminated → Kafka
  → publishes enforcement.violation → Kafka
  ← 401
```

From that instant:
- Any further request with that token fails at step one.
- Any third-party app's access token linked to that session stops working,
  because `/userinfo` re-checks liveness and now finds nothing.
- The gateway cookie is cleared and the browser is bounced to login.

One deleted Valkey key revokes access everywhere, immediately. That is the
concrete payoff of using opaque session tokens instead of self-verifying ones.

---

# Part 5 — Every "If and But"

The exhaustive list of edge cases and how each is handled.

## Login

| Situation | Result |
|---|---|
| Email doesn't exist | 401, indistinguishable from wrong password |
| Email exists, no password set | 401, same shape |
| Password wrong | 401 `auth.login_failure` |
| Password right, account suspended | 403 `ACCOUNT_SUSPENDED` (checked *after* password) |
| Geo Service down or circuit open | **Denied** `LOCATION_UNVERIFIED`, never allowed |
| Address valid but not in the geo database | **Denied** — "don't know" is not a pass |
| Private/internal address | Returns `US` — local-development fixture only |
| Policy Service down | **Denied** `POLICY_UNAVAILABLE` |
| Country in blocked list | Denied, even if also in the allow list |
| Allow list defined, country absent | Denied |
| No policy rows at all | Allowed — no restriction defined |
| Tenant hard cap set | Wins outright; user/OU values for that attribute ignored |
| Six-digit code wrong | Denied, failure counter incremented |
| 5th consecutive wrong code | Device locked 5 minutes, `device.locked` published |
| Code correct while locked | Denied without even checking the code |
| Code from 30s ago or 30s ahead | **Accepted** — drift window |
| Code from 90s ago | Rejected |
| No device enrolled at all | `NO_SECOND_FACTOR_ENROLLED` |
| Device Service down | `SECOND_FACTOR_UNAVAILABLE` — denied, not bypassed |
| Push: user taps Deny | `PUSH_DENIED` |
| Push: no answer in 60s | `PUSH_TIMEOUT`, challenge deleted |
| Push: answered at second 75 | Challenge still exists (90s), write succeeds, but login already timed out |
| Push: answered twice | Second attempt rejected as already resolved |
| Push send itself fails | Challenge deleted immediately, error surfaced |
| Session Service down | **503**, not a denial — a real outage, reported as one |
| Login request retried after a dropped response | Same session replayed, not a second one |
| Idempotency key reused with different user | Conflict error, never a wrong session |

## Sessions

| Situation | Result |
|---|---|
| Token guessed | Impossible in practice — 256 bits of randomness |
| Valkey keyspace stolen | Only hashes exposed; not usable as credentials |
| Session expired | Key auto-deleted by Valkey; lookups simply find nothing |
| Terminate an already-terminated session | `SessionNotFoundException`, not a silent success |
| Two simultaneous terminations | GETDEL guarantees exactly one wins, one audit event |

## Enforcement

| Situation | Result |
|---|---|
| Session already killed | 401, **no audit event** (no identity to attribute it to) |
| Geo unresolvable mid-session | Request denied, **session left alive** |
| Policy Service unreachable mid-session | Request denied, **session left alive** |
| Policy actively denies | Session **destroyed**, `enforcement.violation` published |
| Same user, same country, twice in 10s | Second uses the 30s cache — but session validity is still re-checked live |
| Two users, same company and country | Different cache keys — per-user policy overrides respected |

## Gateway

| Situation | Result |
|---|---|
| No cookie, no header | Redirected to login |
| Gateway not configured with a client id | Plain 401 instead of a redirect |
| Upstream address not configured | 503 with an explicit message |
| Cookie present but session killed | Cookie cleared, redirected to login — not an error page |
| Caller forges `X-Auth-User-Id` | Stripped before forwarding; only the gateway's value arrives |
| Caller sends `X-Session-Token` | Never forwarded to the upstream app |
| Tampered `state` parameter | Only honoured if it starts with `/proxy`; otherwise safe default |
| Upstream app unreachable | 502 |
| Upstream returns an error | That exact status and body are passed through |
| App tries to set its own cookies | **Currently stripped** — known limitation |

## OpenID Connect

| Situation | Result |
|---|---|
| Unknown client id | Error page, **no redirect anywhere** |
| Redirect address not registered | Error page, no redirect |
| Code reused | Rejected — GETDEL made it single-use |
| Code older than 60 seconds | Expired, rejected |
| Code used by a different client | Rejected |
| Wrong client secret | Rejected |
| Session belongs to a different company than the app | Rejected |
| Underlying session killed | Access token stops working immediately at `/userinfo` |

## Infrastructure

| Situation | Result |
|---|---|
| A Kafka broker dies | Two replicas remain; nothing lost |
| Audit Service down for an hour | Events queue in Kafka; consumed on return |
| An audit event repeatedly fails to save | Retried with backoff, then parked in the dead-letter topic |
| The same audit event delivered twice | Duplicate check by event id skips it |
| OpenBao restarted | Comes back **sealed**; services needing certificates fail to start until unsealed. Correct by design. |
| A service is slow | Caller times out at 5 seconds |
| A service keeps failing | Circuit opens after 5 calls at >50% failure; 30-second cooldown |
| A service returns an expected 404/401 | Excluded from failure counting — does not trip the breaker |

---

# Part 6 — What Is Deliberately Not Built

Listed honestly, because knowing the edges of a system matters as much as
knowing its contents.

- **Certificate and token renewal.** Service certificates and OpenBao tokens
  are issued with 30-day lifetimes and no renewal process. Real production
  wants short lifetimes plus automatic renewal.
- **Automatic OpenBao unsealing.** Manual, by design at this stage.
- **Per-company password peppers.** One platform-wide pepper today.
- **Cookie separation at the gateway.** An application's own cookies are
  stripped rather than separated from the gateway's.
- **Token refresh at the gateway.** When the cookie expires the user is sent
  through login again rather than refreshed silently.
- **Email in the header-based identity forwarding.** Only present on the
  cookie path.
- **IPv6 geolocation.** Only four-part IPv4 addresses are accepted.
- **Granular roles.** Two fixed roles, `USER` and `ADMIN`.
- **Real-time directory synchronisation.** Polling, not push notifications.
- **Database redundancy.** A single PostgreSQL instance locally; a prepared
  but unapplied Kubernetes manifest exists for the real deployment.
- **Multiple upstream applications per gateway.** One fixed upstream address.
- **Event-driven push waiting.** Currently polls once per second, holding a
  thread.

Every one of these is a known, recorded decision with a reason — see
`DECISIONS.md` for the full history, including the bugs found and fixed along
the way.
