# iam-device-svc

Service 9 in `BUILD_PLAN.md`'s build order — second-factor device
enrollment and verification: TOTP and FCM push approve/deny. One enrolled
device record supports both factors (confirmed with product owner). Called
by `iam-auth-svc` as a step inside the same orchestrated login (AP-1) — no
separate MFA login endpoint.

## Contract

`iam-platform-docs/contracts/iam-device-svc.yaml`:
- `POST /api/v1/devices/enroll`
- `POST /api/v1/devices/totp/verify`
- `POST /api/v1/devices/push/send` — blocks the HTTP call itself for up to
  60s waiting on `/push/respond` (confirmed design; no separate polling
  endpoint). Callers need a >60s read timeout for this call specifically.
- `POST /api/v1/devices/push/respond`

## Schema

`devices` table (Postgres, `device_db`):

| Column | Notes |
|---|---|
| `id`, `tenant_id`, `user_id` | |
| `status` | `PENDING` until first successful TOTP verify, then `ACTIVE` |
| `totp_secret_ciphertext`, `totp_secret_nonce` | AES-256-GCM, per-tenant DEK from OpenBao |
| `fcm_token` | nullable — set at enroll time if this device also supports push |
| `failed_totp_attempts`, `locked_until` | lockout: 5 failed attempts -> 5 minute cooldown |

"The" device for a tenant/user is always the most recently enrolled row
(one device, both factors — re-enrolling replaces which row is current).

Push-approval challenges live entirely in Valkey (`push-challenge:<id>`,
TTL 90s), never Postgres — ephemeral state, not an audit/system-of-record
fact, same reasoning as `iam-session-svc`'s session records.

## Crypto

- **TOTP secrets:** AES-256-GCM, per-tenant DEK generated and cached from
  OpenBao KV v2 (`totp-dek/<tenantId>`, get-or-create) — same pattern as
  `iam-identity-svc`'s password pepper, just per-tenant instead of
  platform-wide. Not routed through OpenBao Transit (no bootstrap tooling
  yet, same reasoning as the pepper's own deviation).
- **TOTP algorithm:** hand-rolled RFC 6238 (HMAC-SHA1, 6 digits, 30s step,
  ±1 step drift window) — no new dependency; the algorithm is ~20 lines and
  long-standardized. Verified against the RFC's own published test vectors
  (`TotpGeneratorTest`).
- **Base32:** hand-rolled RFC 4648 (no padding) for the provisioning
  secret/URI — not in the JDK, too small to warrant a dependency.

## Push (FCM)

Real FCM HTTP v1 API calls, authenticated via a service-account JSON loaded
from OpenBao (`fcm-service-account`, field `json`) — never from a local
file at runtime. Uses `com.google.auth:google-auth-library-oauth2-http`
(Tier-3 dependency, confirmed with product owner 2026-09-16) only for the
OAuth2 token exchange; the actual send is a plain REST call through the
project's own `ResilientHttpClient`, not the full `firebase-admin` SDK.

**Loading the credential into OpenBao (one-time, per environment):**
```
curl -s -X POST http://localhost:8200/v1/secret/data/fcm-service-account \
  -H "X-Vault-Token: dev-root-token" \
  -d "{\"data\":{\"json\": $(cat /path/to/service-account.json | python -c 'import json,sys;print(json.dumps(sys.stdin.read()))')}}"
```

## Second factor is always required (MVP)

`BUILD_PLAN.md`'s login flow diagram calls `iam-device-svc` unconditionally
— there's no policy toggle to make MFA optional in this MVP. This is a
specific, fixed policy configuration of the one factor engine (AP-1), not a
hardcoded separate path: `iam-auth-svc` calls the same `/login` endpoint
regardless, and whether a second factor is even possible is entirely
data-driven (does this user have an enrolled device).

## Known gap: no retry on device-svc calls from iam-auth-svc

`totp/verify` (increments a failed-attempt counter) and `push/send` (sends
a real notification, creates a challenge) are both mutating and neither has
an idempotency key yet, unlike `iam-session-svc`'s `issue` endpoint. So
`iam-auth-svc`'s Resilience4j retry for `device-svc` is disabled
(`max-attempts: 1`) — a lost response fails the login closed rather than
risking a double-counted lockout attempt or a duplicate push. Logged in
`docs/DECISIONS.md`, Service 9 entry.

## TEST GATE (BUILD_PLAN.md §6)

**TOTP — fully verified live:** enroll via QR (curl standing in for the
not-yet-built mobile app) → TOTP code accepted by `iam-auth-svc`'s real
login flow → session issued. Lockout (5 wrong attempts → `LOCKED`) also
verified live. See `docs/DECISIONS.md`, Service 9 entry, for full detail.

**Push — partially verified, one honest gap:** the real FCM credential's
auth and IAM permission were confirmed working against the actual
`testing-ratnesh` Firebase project, and `device-svc`'s own error handling
(fast-fail `503`, not a 60s hang, on delivery failure) was confirmed live.
A full "phone taps Approve → `iam-auth-svc` proceeds" round trip needs a
genuine FCM registration token, which only a real Android device running
the Mobile Authenticator app (Service 12, not built yet) can produce —
same class of external blocker as Service 8's Google Workspace dependency.
The approve/deny/timeout logic itself is covered by `DeviceServiceTest`'s
mocked-FCM unit tests.
