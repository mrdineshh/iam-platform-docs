# iam-geo-svc

Service 3 in `BUILD_PLAN.md`'s build order — stateless IP -> country/region/
city resolver. No database, no outbound calls, no Kafka publishing (Kafka
role is explicitly "none" per BUILD_PLAN.md Section 4.1).

## Contract

`iam-platform-docs/contracts/iam-geo-svc.yaml` — `GET /api/v1/resolve?ip=<ip>`.

## Real data source: DB-IP Lite (not MaxMind GeoLite2)

`BUILD_PLAN.md` calls for bundling the real MaxMind GeoLite2 database.
GeoLite2 requires a MaxMind account + license key, which wasn't available
when this service was first built, so it shipped with a bundled test dataset
instead (see `iam-platform-docs/docs/DECISIONS.md`, Service 3 entry, for that
interim decision). This has now been swapped for **DB-IP Lite** (Country
edition) — a free-forever `.mmdb` database, no account or license key
required, wire-format-compatible with GeoLite2/GeoIP2 (both use the same
MaxMind DB binary format), read via the open-source `com.maxmind.db:maxmind-db`
reader library. Only `GeoLookupService`'s data source changed — API contract,
resilience behavior, and every downstream caller are unaffected.

- **Country only, no region/city.** DB-IP's free tier only ships country
  granularity; `region`/`city` in `GeoResolution` are always `null` now. This
  matches actual usage — `iam-policy-svc` only implements country-based
  policy (see its own scope-narrowing note), so no caller currently reads
  region/city anyway.
- **License:** DB-IP Lite is CC BY 4.0 — attribution required. This product
  includes IP geolocation data created by DB-IP, available from
  https://db-ip.com.
- **Bundled file goes stale.** `src/main/resources/geoip/dbip-country-lite.mmdb`
  is a snapshot (downloaded 2026-09-16). DB-IP publishes a new file monthly;
  re-download and replace this file periodically to keep lookups accurate.
- IPv6 is not yet supported (same limitation as before the swap).

## LOCAL-DEV-ONLY fixture: private IP ranges

Any RFC 1918 private address (10.x, 172.16-31.x, 192.168.x) resolves to a
fixed test country, not "unresolved." Added 2026-09-17 (Service 11): a
request reaching a service through a Docker Compose host-mapped port
arrives from Docker's internal bridge gateway (a private address, e.g.
`172.19.0.1`), which no real GeoIP database has an entry for -- without
this, every locally-tested OIDC login would be denied as "location could
not be verified" even on the intended success path. This can never fire
against a real deployment; a real ingress only ever sees real public
client IPs. See `docs/DECISIONS.md`, Service 11 entry.

## Callers / callees

- **Called by:** `iam-auth-svc` (Service 7) and `iam-enforcement-svc`
  (Service 10) for location-based policy decisions, via `iam-service-kit`'s
  Resilience4j-wrapped HTTP client.
- **Calls:** nothing.
- **Produces:** nothing to Kafka.

## Behavior

`resolved: false` with null `country`/`region`/`city` is a normal `200`, not
an error — it means the IP isn't in the dataset. Callers must treat this as
unresolved/high-risk, never as an automatic pass (BUILD_PLAN.md Section 4.6).

## Build / run

```
./gradlew build
./gradlew bootRun
```

No infra dependencies required to run this service locally beyond what
`iam-service-kit`'s autoconfiguration expects (Kafka/OpenBao addresses via
env vars — unused by this service's own logic, but present on the classpath
transitively).

## TEST GATE (BUILD_PLAN.md §6)

`curl` a known IP (`8.8.8.8`) -> resolves to its correct country. Also
verified: a second known range, an IP outside the dataset (`resolved:false`,
still `200`), a malformed IP (`400`), and a missing `ip` parameter (`400`).
