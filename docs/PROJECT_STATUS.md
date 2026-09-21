# Project Status — Read This First In A New Session

**Last updated:** 2026-09-21

This is the handoff document. It states what this project is, exactly what is
built and verified, exactly what is not, and what remains for the Minimum
Viable Product (the smallest real version worth shipping). Read this plus
`CLAUDE.md` and `BUILD_PLAN.md` before doing any work.

---

## 1. What This Project Is

A multi-tenant Identity and Access Management platform (a hosted service that
proves who a person is and decides what they may access, serving many
customer companies from one deployment). It provides single sign-on to
third-party applications, a unified authentication engine (password plus a
second factor), contextual access control by location, and — its
distinguishing feature — **continuous enforcement**: access is re-checked on
every request after login, not only at the login screen, and a session can be
killed mid-use.

**Architecture:** polyrepo microservices. Each service is its own Git
repository, checked out side by side in one workspace directory, orchestrated
locally by a single `docker-compose.yml` that lives in this umbrella repo.

**Primary stack:** Kotlin + Spring Boot backends, Next.js login portal, React
+ Vite admin console, PostgreSQL, Valkey, Kafka, OpenBao.

**Key documents in this repo:**
| File | What it is |
|---|---|
| `CLAUDE.md` | Non-negotiable principles (AP-1 to AP-8), tech stack, what not to build |
| `BUILD_PLAN.md` | The architecture and build order; Section 3 holds the deviation table |
| `docs/BRD.md` | Full numbered business requirements |
| `docs/ENGINEERING_GUARDRAILS.md` | Operating rules, error-handling pattern, Definition of Done |
| `docs/DECISIONS.md` | The full decision log — every service, every trade-off, every bug found and fixed. ~1800 lines. |
| `docs/SYSTEM_GUIDE.md` | Plain-language overview of the whole system |
| `docs/INTERNALS.md` | Deep technical walkthrough: every table, keyspace, algorithm, request trace, and edge case |

---

## 2. Repository Layout

```
C:\Iam_core_Platform\          <- this umbrella repo (docs, docker-compose, infra)
C:\workspace\                  <- all service repos, side by side
├── iam-service-kit/           (shared library, not a running service)
├── iam-audit-svc/
├── iam-tenant-svc/
├── iam-geo-svc/
├── iam-identity-svc/
├── iam-policy-svc/
├── iam-session-svc/
├── iam-auth-svc/
├── iam-device-svc/
├── iam-enforcement-svc/
├── iam-oidcprovider-svc/
├── iam-login-portal/
├── iam-admin-console/
├── service-template/
└── mtls-entrypoint.sh         <- shared build-context file, canonical copy lives
                                  in this umbrella repo at infra/mtls-entrypoint.sh
```

The umbrella repo pushes to `github.com/mrdineshh/iam-platform-docs` on
branch `main`. Every service repo pushes to
`github.com/ratneshsingh-dev/<name>` on branch `master`. All repos are
currently clean and fully pushed.

---

## 3. What Is Built And Verified

All twelve running components below are implemented, tested live against the
real running stack (not mocked), and pushed.

| # | Service | What it does | Storage |
|---|---|---|---|
| 1 | `iam-audit-svc` | Consumes audit events from Kafka, stores them permanently. Dead-letter topic for failures. | `audit_db` |
| 2 | `iam-tenant-svc` | Companies (tenants) and registered third-party app credentials | `tenant_db` |
| 3 | `iam-geo-svc` | Internet address to country, offline lookup file, no database | none |
| 4 | `iam-identity-svc` | Users, Argon2id password hashing with an OpenBao-held pepper, roles | `identity_db` |
| 5 | `iam-policy-svc` | Access rules, merge-with-hard-cap resolver across tenant/group/user levels | `policy_db` |
| 6 | `iam-session-svc` | Session issue/validate/terminate. Opaque random tokens, stored hashed in Valkey. Idempotency protection. | Valkey |
| 7 | `iam-auth-svc` | The login orchestrator — the only service permitted to issue a session | none |
| 9 | `iam-device-svc` | Second factor: rotating six-digit codes (AES-256-GCM encrypted secrets, per-tenant keys) and push approval | `device_db` + Valkey |
| 10 | `iam-enforcement-svc` | Continuous per-request enforcement, **plus** the reverse-proxy gateway | Valkey (cache only) |
| 11 | `iam-oidcprovider-svc` | Standards-based single sign-on for third-party apps | Valkey |
| 13 | `iam-login-portal` | The branded login web page (Next.js) | none |
| 14 | `iam-admin-console` | Tenant administrator web interface (React + Vite) | none |

Plus `iam-service-kit`: shared correlation-ID propagation, the
resilience-wrapped HTTP client, the Kafka audit publisher, the OpenBao
client, and mutual-TLS support.

### Infrastructure, all working

- **PostgreSQL** — one server, five separate databases, one per service
- **Valkey** — session, push-challenge, authorization-code and cache storage
- **OpenBao** — real server mode with Raft storage (not the throwaway dev
  mode), acting as certificate authority, secret store, and access-control
  system via AppRole
- **Kafka** — genuine 3-broker KRaft cluster, replication factor 3,
  `min.insync.replicas` 2, producers using `acks: all`
- **Jaeger** — distributed tracing
- **`whoami`** — a tiny stand-in application used to prove the gateway works

### Security features completed this session

- **Mutual TLS between services.** Four purely internal services
  (`session`, `geo`, `identity`, `device`) require a client certificate on
  their inbound listener. The other five fetch certificates so they can act
  as clients, but keep plain-HTTP inbound listeners because real browsers and
  the Node server call them directly and cannot trust a self-signed internal
  certificate authority. Closes deviation **D2**.
- **Multi-broker Kafka.** Closes deviation **D4a**.
- **OpenBao hardening.** Real persistence, AppRole instead of a shared root
  token.
- **The gateway (policy enforcement point in front of a real app).** The
  Enforcement Service can now sit in front of an application, authenticate
  browsers itself via a cookie, re-check policy on every forwarded request,
  and inject trusted identity headers. Verified end-to-end against `whoami`.

---

## 4. What Is NOT Built

### Two planned services do not exist at all

| # | Service | Why not | Impact |
|---|---|---|---|
| 8 | `iam-directory-svc` | Blocked on Google Workspace administrator access — an external dependency, never obtained | No Google Workspace login, no automatic user synchronisation. Users are created directly instead. |
| 12 | `iam-mobile-android` | Not built | See below |

**Important nuance on the missing mobile app:** the rotating six-digit code
path works fully **today** with any standard authenticator application
(Google Authenticator, Authy, etc.), because enrolment returns a standard
`otpauth://` provisioning link. This was verified live. What does *not* work
end-to-end is the **push-approval** path: the server side is built and its
credentials were confirmed working against a real Firebase project, but
nobody can tap "Approve" without the custom Android app existing. That gap is
recorded honestly in `DECISIONS.md` under Service 9.

**Note:** `SYSTEM_GUIDE.md` describes 14 services. That count includes the
mobile app, which does not exist yet.

### Deployment does not exist — nothing at all

This is the single largest remaining body of work. There is:
- **No** infrastructure-as-code (no OpenTofu configuration of any kind)
- **No** Kubernetes cluster, and **no** Helm charts for any service
- **No** operator installations (CloudNativePG, Strimzi)
- **No** ingress configuration (Envoy Gateway / Gateway API)
- **No** continuous-deployment pipeline (ArgoCD)
- **No** monitoring stack (Prometheus, Grafana, Loki)
- **No** real domain, DNS, or TLS certificates

The only deployment artefact that exists is
`infra/postgres/cloudnativepg-cluster.yaml` — a prepared, **never applied**
Kubernetes manifest for a redundant PostgreSQL cluster. It contains
placeholder values (storage bucket, credentials) that must be filled in.

### The third-party application is not connected

The gateway is built and proven against a stand-in, but has never been
pointed at a real application (the intended one being "Pulse"). The setup
steps are known and documented, but have not been executed.

---

## 5. Deviation Status (`BUILD_PLAN.md` Section 3)

| # | Status |
|---|---|
| D1 — Enforcement Service is Kotlin, not Go | **Open.** Deliberate; only the language differs from the target stack. |
| D2 — No inter-service authentication | **CLOSED** — real mutual TLS via OpenBao |
| D3 — Two fixed roles instead of granular permissions | **Open.** `USER` and `ADMIN` only. |
| D4a — Single-broker Kafka | **CLOSED** — real 3-broker cluster |
| D4b — Single PostgreSQL, no redundancy | **Open by decision.** Deployment-time work; documented, deliberately not simulated locally. |
| D5 — Directory synchronisation is polling, not push | **Moot** until Service 8 exists. |

---

## 6. Known Smaller Gaps

All recorded in `DECISIONS.md`, none hidden:

- **Gateway strips an application's own cookies.** It removes the entire
  `Cookie` header, so an application behind it cannot keep its own
  cookie-based state. Needs finer-grained cookie separation before fronting
  an app that relies on cookies.
- **No token refresh at the gateway.** When the cookie expires the user is
  sent through login again rather than refreshed silently.
- **`X-Auth-User-Email` only on the cookie path**, not the header path (the
  header path has no source for email without adding a new dependency).
- **One platform-wide password pepper**, not per-company.
- **No certificate or token renewal.** 30-day lifetimes, no renewal process.
- **No automatic OpenBao unsealing.** Manual by design at this stage.
- **IPv4 only** for geolocation.
- **Push waiting holds a thread**, polling once per second for up to 60
  seconds. Fine at MVP scale, not at high scale.
- **Local geolocation fixture:** private network addresses resolve to `US` so
  local testing works. Never triggers behind a real ingress.

---

## 7. Running It Locally

```bash
cd C:\Iam_core_Platform
docker compose up -d
```

**Critical step that is easy to miss:** OpenBao comes back **sealed** after
any restart. Until it is unsealed, all nine mutual-TLS services will fail to
start (exit code 22). To unseal and re-provision:

```bash
cd C:\Iam_core_Platform\infra\openbao
python bootstrap.py
cd C:\Iam_core_Platform
docker compose up -d
```

This is correct security behaviour, not a bug. The script is idempotent.

### Ports

| Service | Port |
|---|---|
| PostgreSQL | 5432 (user `iam`, password `localdev`) |
| Valkey | 6379 |
| OpenBao | 8200 |
| Kafka | 9092 |
| Jaeger UI | 16686 |
| `iam-audit-svc` | 8081 |
| `iam-tenant-svc` | 8082 |
| `iam-geo-svc` | 8083 |
| `iam-identity-svc` | 8084 |
| `iam-policy-svc` | 8085 |
| `iam-session-svc` | 8086 |
| `iam-auth-svc` | 8087 |
| `iam-device-svc` | 8088 |
| `iam-enforcement-svc` | 8089 |
| `iam-oidcprovider-svc` | 8090 |
| `whoami` (test stand-in) | 8091 |
| `iam-login-portal` | 3001 |
| `iam-admin-console` | 5173 |

### Testing notes for a future session

- The four mutual-TLS services **cannot** be called with Windows-native
  `curl` (its Schannel backend fails to present client certificates here).
  Use a Linux container on the same Docker network instead:
  ```bash
  MSYS_NO_PATHCONV=1 docker run --rm --network iam_core_platform_default \
    -v "/c/Iam_core_Platform/infra/openbao/secrets/test-client:/certs:ro" \
    curlimages/curl:latest \
    curl -sk --cert /certs/cert.pem --key /certs/key.pem "$@"
  ```
- `MSYS_NO_PATHCONV=1` is needed whenever passing container-side absolute
  paths, otherwise git-bash rewrites them into Windows paths.
- Logging in requires a resolvable public address — use `8.8.8.8` as
  `sourceIp`, not a private one, unless relying on the local fixture.
- The login request body is
  `{tenantId, email, password, sourceIp, totpCode}` — note `email`, not
  `username`.

---

## 8. What Remains For MVP — In Priority Order

**1. Deploy it somewhere real.** Nothing else can be demonstrated until this
exists. Two options were discussed:
- **Single cloud virtual machine running the existing `docker-compose.yml`**
  — roughly one day of work, no architectural change, no new tooling, and it
  graduates cleanly to Kubernetes later. This was the recommended MVP path.
- **Full Kubernetes (GKE) build-out** — roughly 7–10 days: OpenTofu, Helm
  charts for every service, operators, ingress, monitoring, CI/CD.

Note: **Cloud Run is not viable** for this architecture — it cannot host
Kafka, CloudNativePG, OpenBao, or Valkey, and adopting it would force
substitutions that `CLAUDE.md` explicitly rejects.

**2. Connect the real third-party application.** Register it, point the
gateway's upstream address at it, configure real HTTPS (the cookie is marked
`Secure`, so plain HTTP will silently fail), and confirm whether that
application needs its own cookies — if it does, the cookie-separation gap
above must be closed first.

**3. Build `iam-mobile-android` (Service 12)** if the push-approval path
needs to be demonstrated. Not needed for the six-digit code path.

**4. Build `iam-directory-svc` (Service 8)** if Google Workspace login is
required. Still blocked on external administrator access.

**5. Close the smaller gaps** in Section 6 as each becomes relevant.

---

## 9. Suggested Opening Prompt For A New Session

> Read `docs/PROJECT_STATUS.md`, `CLAUDE.md`, and `BUILD_PLAN.md` first.
> I want to work on: [X].
> Follow the existing architectural principles, do not modify a previously
> built service's published interface without confirming with me, and ask
> rather than assume if something is underspecified.
