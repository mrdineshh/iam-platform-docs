# How This System Works — Complete Plain-Language Guide

This document explains, in simple words, how this Identity and Access
Management (a system that checks who a person is and what they are allowed to
do) platform is built, how its pieces talk to each other, what happens on a
real login, and what it would take to run it for real users. No shortened
terms are used without first spelling out what they mean.

---

## 1. The Big Picture

This is not one big program. It is 14 small, independent programs (called
"microservices" — small services, each doing one job) that talk to each other
over the network. Each one:

- Does exactly one job (for example, one service only knows about user
  passwords, another only knows about company policies).
- Has its own private database — no service is allowed to read another
  service's database directly. If Service A needs information owned by
  Service B, Service A must ask Service B over the network, the same way a
  browser asks a website for a page.
- Can be stopped, restarted, or upgraded without stopping the others.

Why split it up like this instead of one big program? Because a security
system like this has very different concerns bundled together (checking
passwords, checking the user's location, remembering who is logged in,
recording every event for audit purposes) and splitting them means:
- A bug in one small service (say, the location checker) cannot crash the
  entire login system.
- Different services can be scaled up separately. For example, the "checking
  if a session is still valid" service gets hit on every single click a user
  makes, while the "create a new company" service is used maybe once a week —
  they do not need the same amount of computing power.

---

## 2. The 14 Services, In Plain Words

| Service name | What it actually does, in plain words |
|---|---|
| **Tenant Service** (`iam-tenant-svc`) | Keeps the list of companies ("tenants") using this system. Every other piece of data belongs to one tenant. |
| **Geo Service** (`iam-geo-svc`) | Takes an internet address (an "IP address" — a numeric address identifying a device on the internet) and tells you which country it is coming from. Has no database of its own — it uses an offline lookup file (MaxMind GeoLite2) bundled inside it. |
| **Identity Service** (`iam-identity-svc`) | Keeps the list of actual human users: their email, their status (active/suspended), their role. |
| **Policy Service** (`iam-policy-svc`) | Keeps the rules: "users from this company can only log in from these countries," "this specific person is blocked from this specific thing no matter what," and so on. It merges company-wide rules with more specific per-user rules. |
| **Session Service** (`iam-session-svc`) | Once someone logs in successfully, this service remembers "this person is currently logged in" using a random one-time code (a "token"). Every later request shows this code to prove it's really them. It can also instantly delete that code, logging the person out immediately from anywhere. |
| **Authentication Service** (`iam-auth-svc`) | The "traffic conductor" of login. When someone tries to log in, this service is the only one allowed to actually decide "yes, let this person in" — it does this by calling several of the services above in sequence and combining their answers. |
| **Device Service** (`iam-device-svc`) | Handles the second security check beyond a password — a 6-digit rotating code (TOTP, Time-based One-Time Password) or a push notification ("Approve this login?") sent to the person's phone. |
| **Enforcement Service** (`iam-enforcement-svc`) | The security guard that keeps checking *after* login, not just at the door. On every single request made after login, it re-checks: is this session still valid? Is the person still in an allowed location? Do the current rules still allow this? If not, it kills the session immediately, mid-use. |
| **OpenID Connect Provider Service** (`iam-oidcprovider-svc`) | This is what lets *other* applications (like an internal dashboard tool) say "let this platform handle login for me" using a well-known industry standard for login called OpenID Connect (OIDC), which is built on top of another standard called OAuth 2.0. |
| **Audit Service** (`iam-audit-svc`) | The permanent record keeper. Every important thing any service does (a login, a failed login, a session being killed, a policy being changed) gets written here permanently, for security review later. |
| **Login Portal** (`iam-login-portal`) | The actual web page a real person sees and types their password into. Built with a web framework called Next.js. |
| **Admin Console** (`iam-admin-console`) | The web page a company's administrator uses to configure their company's settings, users, and rules. Built with a web framework called React, using a build tool called Vite. |
| **Mobile Authenticator App** (`iam-mobile-android`) | An Android phone app used for the second security check above (approving push notifications, generating the rotating 6-digit code). |
| **Shared Service Kit** (`iam-service-kit`) | Not a running service — a shared library (a package of reusable code) that every backend service includes, so they don't each reinvent the same plumbing: how to call another service safely, how to publish an audit record, how to talk to the secrets vault. |

---

## 3. How Services Talk To Each Other

There are exactly two ways any service ever talks to another:

### Method 1 — Direct request-and-answer (synchronous calls)

This is the same idea as a web browser requesting a web page: Service A sends
a request over the network directly to Service B, and waits for Service B to
answer before continuing. This is used whenever the answer is needed
*immediately* to keep going — for example, the Authentication Service cannot
decide whether to let someone in without first getting an answer back from the
Policy Service.

Every one of these direct calls has three safety nets built in (using a
library called Resilience4j — "resilience" meaning "the ability to recover
from failure"):
- **Timeout** — never wait forever for an answer. If a service doesn't
  respond within a set time, give up and treat it as failed, rather than
  freezing.
- **Retry** — if a call fails, try again a few times with an increasing wait
  between attempts, in case it was just a brief hiccup.
- **Circuit breaker** — if a service has failed many times in a row, stop
  even trying to call it for a short cooldown period, and immediately return
  "this feature isn't available right now" instead of piling up more failed
  attempts on an already-struggling service.

**Very important safety rule used everywhere in this system:** if a service
that is needed to make a security decision cannot be reached at all (for
example, the Geo Service is down and we cannot figure out what country the
request is coming from), the answer is **always "deny," never "allow."**
This is called "never fail open" — an unknown situation is treated as
dangerous, never as a free pass.

### Method 2 — Fire-and-forget event messages (asynchronous, via Kafka)

This is used only for one purpose right now: **recording history for audit
purposes.** When something security-relevant happens (a login succeeded, a
password was wrong, a session was killed), the service that did it doesn't
call the Audit Service directly. Instead, it drops a small note into a shared
message system called **Kafka** (explained fully in Section 4), and moves on
immediately without waiting for anyone to read that note. The Audit Service
reads these notes whenever it's ready and saves them permanently.

### Method 3 — Proving who's really calling (mutual TLS)

For the four purely internal services that are never touched by an end
user's web browser directly (Session, Geo, Identity, Device), every call
between services must additionally prove its identity using a security
technique called **mutual TLS** (TLS is "Transport Layer Security," the same
encryption technology behind the padlock icon in a web browser; "mutual"
means *both* sides prove who they are with a certificate, not just the
server). This is done using an internal certificate authority (a trusted
issuer of digital ID cards for computers) run by a secrets-management tool
called **OpenBao**. Every service fetches its own short-lived digital
certificate from OpenBao when it starts up and presents it on every call it
makes, so that even inside our own private network, a service must prove its
identity before another service will talk to it — not just "whoever's
calling me from the network" is trusted blindly.

---

## 4. The Two Supporting Systems: Kafka and Valkey

### Kafka — the shared, durable notice board for audit events

Kafka is a piece of infrastructure whose entire job is: many different
programs can drop messages onto it, and many different programs can read
those messages later, without the writer and the reader ever needing to be
online at the exact same moment. Think of it like a notice board where people
pin notes, and other people come read the board whenever they get a chance —
rather than a phone call where both people must be on the line at once.

**What it's used for here:** every service that does something
security-relevant pins a note ("user X logged in successfully at this time
from this location") onto a shared board called `audit-events`. The Audit
Service reads every note on that board and saves it permanently to its
database.

**What would happen without it?** Every single service would instead have to
directly call the Audit Service every time something happened, and *wait*
for that call to succeed, the same way they call the Policy Service or the
Geo Service. This creates two serious problems:
1. If the Audit Service is ever slow or briefly down, every *other* action in
   the entire system (logins, session checks, everything) would slow down or
   fail too, purely because the record-keeper had a hiccup. That's backwards
   — recording history should never be able to block someone from logging in.
2. If a new tool needs to read the same events later (for example, a future
   security monitoring dashboard), it would have to convince every single
   one of the other 10 services to also call it directly. With Kafka, that
   new tool just starts reading the same shared notice board — nothing else
   has to change.

We also run Kafka with **3 copies of the notice board** (called
"replication"), not just 1. This means if one physical machine holding a
copy of the board goes down, two other copies still exist and nothing is
lost. Without this, a single machine failure could permanently lose audit
records — which, for a security system, is not acceptable.

### Valkey — the fast, short-term memory

Valkey is an extremely fast, in-memory data store (an open-source,
community-governed continuation of a well-known tool called Redis, after
Redis changed its licensing terms in 2024). "In-memory" means it keeps data
in the computer's fast working memory (RAM) instead of on a hard disk, which
makes reading and writing to it enormously faster than a normal database —
at the cost of it not being meant for permanent, once-in-a-lifetime storage.

**What it's used for here:**
1. **Storing active login sessions.** When someone logs in, their one-time
   login code and the fact that "this person is logged in" are stored in
   Valkey, not the main database. Every later click the user makes needs
   this checked — potentially thousands of times per second across all
   users — and Valkey can answer that check almost instantly.
2. **Briefly caching policy decisions** inside the Enforcement Service, so
   that if the exact same person from the exact same location is re-checked
   again 10 seconds later, it doesn't have to re-ask the Policy Service from
   scratch every single time — it remembers the answer for a short window
   (30 seconds) before checking fresh again.
3. **Tracking "waiting for phone approval" status** for push-notification
   logins — a short-lived state that only matters for about 60 seconds
   while someone is looking at their phone.

**What would happen without it?** Every single request a logged-in user
makes would have to look up "is this session still valid?" directly in the
main permanent database (PostgreSQL) instead. PostgreSQL is built to be
extremely safe and durable (it writes everything to disk, so nothing is
lost even if the power goes out), but that safety comes at the cost of being
much slower for this specific job — millions of tiny "is this still valid"
checks per day. Using Valkey for this fast, temporary, "does this need to
survive a total power loss" data, and reserving PostgreSQL for permanent
records, is a deliberate and common industry pattern.

---

## 5. A Full Real Login, Step By Step

Here is exactly what happens, service by service, when a real person logs in
and later has their session end because they moved to a blocked country.
Every step below is a real network call.

1. The person opens the **Login Portal** web page and types their company
   subdomain, email, and password.
2. The Login Portal sends this to the **Authentication Service**, which is
   the *only* service allowed to decide "yes, log this person in." This is
   deliberate — even though six other services are involved, there is
   exactly one place in the whole system where the final "allow" decision is
   made, so the rule "always check the password and the policy before
   letting someone in" can never be accidentally skipped by some other path.
3. The Authentication Service asks the **Identity Service**: "does this
   email exist for this company, and does this password match?" The
   Identity Service checks the password using a secure password-hashing
   method (Argon2id) combined with a secret ingredient (called a "pepper")
   fetched from **OpenBao**, the secrets vault, rather than storing it in
   plain code.
4. If a rotating 6-digit code was also provided, the Authentication Service
   asks the **Device Service** to confirm the code is correct for this
   person's enrolled phone.
5. The Authentication Service asks the **Geo Service**: "what country is
   this internet address coming from?"
6. The Authentication Service asks the **Policy Service**: "given this
   company's rules and this specific person's rules, is a login from this
   country allowed right now?"
7. If everything above says yes, the Authentication Service asks the
   **Session Service** to create a new session: a random one-time code that
   now means "this person is logged in," stored in **Valkey** for
   fast lookup later.
8. At every one of the steps above, the Authentication Service drops a note
   onto the **Kafka** notice board describing what just happened. The
   **Audit Service** reads these notes and saves a permanent record.
9. The Authentication Service hands the new session back to the **OpenID
   Connect Provider Service**, which is the piece that speaks the standard
   login language other applications understand. It issues a signed token
   (a tamper-proof digital note, signed using a private key stored in
   OpenBao) to the application the person was trying to reach (for example,
   an internal dashboard tool).
10. The person is now logged into that other application.

**Now, later, mid-session:**

11. The person's device changes location — say, they connect through a
    blocked country's network.
12. The very next request they make to any protected resource passes through
    the **Enforcement Service** first (this is the ongoing security guard,
    not a one-time login check). It independently re-asks the **Session
    Service** ("is this session still valid?"), the **Geo Service** ("where
    is this request coming from *right now*?"), and the **Policy Service**
    ("is this still allowed?") — completely fresh, not reusing anything
    decided at login time.
13. Since the new location is blocked, the Enforcement Service immediately
    tells the **Session Service** to delete that session entirely, and drops
    a note onto the **Kafka** notice board recording exactly why the session
    was killed.
14. The person's very next click anywhere fails — their session is gone,
    even though they never explicitly logged out. This is the entire point
    of continuous enforcement: security checks don't stop after the door is
    opened.

---

## 6. What The "Gateway" Piece Adds

A piece built directly into the Enforcement Service lets it act as a
**reverse proxy** — meaning: instead of just answering "yes/no, is this
request allowed," it can actually sit *in front of* another real application
and forward the request onward itself, but only after running the exact
same check as above. If the check fails, the other application never even
sees the request.

This now includes the cookie-translation piece that was originally flagged
as missing: if a plain web browser shows up with no proof of login at all
(no special header, no cookie), the gateway sends it through the platform's
completely normal login page first — the exact same one described in
Section 5 — and when that succeeds, the gateway sets its own cookie on the
browser and lets the original request through. Every request after that
just carries the cookie automatically, the same way any other website's
"remember me" cookie works. If a later request gets denied (wrong location,
policy change), the cookie is deleted and the browser is sent back to the
login page again — it can't just keep using a stale cookie. This is the
piece that lets a real app with its own ordinary cookie-based session (a
real deployed Pulse, for example) sit behind this gateway using its normal
browser behavior, instead of needing to speak this platform's internal
conventions directly.

One piece is still intentionally not built: if the real app behind the
gateway sets its *own* cookies too (separate from the platform's), those
aren't yet kept separate from the platform's own cookie — today the
gateway strips all cookies before forwarding a cookie-authenticated
request onward. Fine for an app that doesn't use cookies itself; a real
app that does would need a small additional piece of work to split the two
apart, flagged, not hidden.

---

## 7. Setting This Up For Real Use (Not Just On One Computer)

Right now, everything above runs as a set of containers (isolated,
lightweight bundles of a program and everything it needs to run) all on a
single computer, using a tool called Docker Compose. That is excellent for
building and testing, but a real product used by real companies needs to run
across multiple actual machines, so that:
- No single machine failing takes down the whole system.
- The system can handle more people logging in at once by adding more copies
  of the busy pieces.

The target technology for this (already decided, not yet built) is
**Kubernetes** — a system that manages many containers spread across many
machines, restarting them automatically if they crash, and moving them to a
healthy machine if one machine dies. Specifically, **Google Kubernetes
Engine (GKE) Autopilot** is the recommended starting point for a first real
deployment: it is still genuine Kubernetes (so nothing about the design
above needs to change), but Google manages the underlying machines for you,
which is far less operational work for a small team's first production
rollout than managing raw servers yourself.

### Roughly how many copies ("instances") of each piece an initial real rollout needs

This is a reasonable starting point for genuinely serving real users
without over-spending — not a hard requirement:

| Piece | How many copies | Why |
|---|---|---|
| Each of the 9 lightweight backend services (Tenant, Geo, Identity, Policy, Device, Audit, plus similar) | 2 copies each | So one copy can be taken down (for an upgrade, or a crash) without any downtime — the other keeps serving. |
| Authentication Service, Session Service, Enforcement Service, OpenID Connect Provider Service | 2–3 copies each | These are on the "critical path" — every single login and every single subsequent request touches them, so they need a bit more headroom than the others. |
| PostgreSQL (the main permanent database) | 3 copies (1 main + 2 standby, using the CloudNativePG tool, already prepared in `infra/postgres/cloudnativepg-cluster.yaml`) | If the main copy fails, one of the standby copies instantly takes over with no data loss, instead of the whole system losing its database. |
| Kafka (the notice board) | 3 copies (already built and proven locally) | Same reasoning — losing one machine should never lose audit history. |
| Valkey (the fast memory store) | 1 copy to start, add a second later as a live backup | Session data matters, but for an initial MVP (Minimum Viable Product — the smallest real version worth shipping), a single well-monitored copy with automatic restart is an acceptable starting point; a second live backup copy is the natural next step, not a hard MVP requirement. |
| OpenBao (the secrets vault) | 1 copy to start (with real backups configured), move to 3 for a proper quorum-based cluster once traffic justifies it | It holds the master keys to everything else, so it deserves care, but a single, well-backed-up copy is a normal and accepted starting point before investing in a full high-availability cluster. |
| Login Portal, Admin Console (the two web pages people actually see) | 2 copies each | So the login page itself is never a single point of failure. |
| The Envoy Gateway (the front door that receives all internet traffic and routes it to the right service) | 2 copies | This is the very first thing any request touches — it must never be a single point of failure. |

Roughly, that totals somewhere around **35–40 running copies (containers)**
spread across a small number of physical machines that Kubernetes manages
for you — you do not manually assign which copy runs on which machine.

### The order things get set up in, for a first real deployment

1. **Provision the underlying cloud infrastructure** — the Kubernetes
   cluster itself, the private network it lives in, and storage — using a
   tool called OpenTofu (an open-source tool for describing infrastructure
   as code, so it can be recreated identically instead of clicked together
   by hand). None of this exists yet; it is the very first piece of new work
   deployment requires.
2. **Install the specialized helper programs Kubernetes itself needs**
   (called "operators") — one that knows how to run a proper PostgreSQL
   cluster (CloudNativePG), one that knows how to run a proper Kafka cluster
   (Strimzi), and one that manages incoming internet traffic (Envoy
   Gateway).
3. **Start the secrets vault (OpenBao)** and unseal it, then set up the
   internal certificate authority and access roles — the exact same steps
   already proven locally, just run against the real cluster instead of one
   Docker container.
4. **Start the real PostgreSQL cluster and the real Kafka cluster**, wait
   until both report healthy, using the manifests already prepared for this
   purpose.
5. **Start Valkey.**
6. **Deploy all 14 of the actual application services**, each pointing at
   the real cluster's internal addresses for the pieces above instead of the
   local Docker Compose names.
7. **Connect the Envoy Gateway** so that real internet traffic can actually
   reach the Login Portal and the OpenID Connect Provider Service from
   outside, and point a real domain name at it.
8. **Turn on monitoring** (Prometheus for metrics, Grafana for dashboards,
   Loki for logs) so problems can actually be noticed and diagnosed, and set
   up an automated deployment pipeline (ArgoCD) so future updates roll out
   in a controlled, repeatable way instead of by hand.

None of steps 1, 2, 7, or 8 exist yet in this project — they are the
deployment work explicitly left for later, exactly as scoped. Everything
from step 3 onward has already been built and proven, just on one computer
instead of a real cluster; moving it there is largely reconfiguration, not a
redesign.
