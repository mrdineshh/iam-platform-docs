FROM gradle:9.7.1-jdk21 AS build
WORKDIR /workspace
COPY iam-geo-svc/ iam-geo-svc/
COPY iam-service-kit/ iam-service-kit/
WORKDIR /workspace/iam-geo-svc
RUN --mount=type=cache,target=/root/.gradle gradle bootJar --no-daemon

FROM eclipse-temurin:21-jre
# curl+jq: AppRole login and PKI cert issuance against OpenBao at startup.
# openssl: bundles the issued PEM cert/key into a PKCS12 keystore. keytool
# (already part of the JRE) builds the matching truststore. See
# mtls-entrypoint.sh and docs/DECISIONS.md, mTLS rollout entry.
RUN apt-get update && apt-get install -y --no-install-recommends curl jq openssl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# City-level GeoIP data: DB-IP "IP to City Lite" (CC BY 4.0, https://db-ip.com -- attribution required).
# Downloaded at build time rather than committed: it is ~130 MB unpacked. Falls back to the previous
# month if this month's file is not published yet. Rebuild monthly to refresh. If both downloads fail
# the build still succeeds and the service uses its bundled country-only database.
ARG DBIP_MONTH=2026-10
ARG DBIP_PREV_MONTH=2026-09
RUN mkdir -p /app/geoip &&     (curl -fsSL "https://download.db-ip.com/free/dbip-city-lite-${DBIP_MONTH}.mmdb.gz" | gunzip > /app/geoip/dbip-city-lite.mmdb      || curl -fsSL "https://download.db-ip.com/free/dbip-city-lite-${DBIP_PREV_MONTH}.mmdb.gz" | gunzip > /app/geoip/dbip-city-lite.mmdb      || rm -f /app/geoip/dbip-city-lite.mmdb)
COPY --from=build /workspace/iam-geo-svc/build/libs/*.jar app.jar
COPY mtls-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENV SERVICE_CN=iam-geo-svc
EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
