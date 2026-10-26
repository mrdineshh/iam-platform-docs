FROM gradle:9.7.1-jdk21 AS build
WORKDIR /workspace
COPY iam-enforcement-svc/ iam-enforcement-svc/
COPY iam-service-kit/ iam-service-kit/
WORKDIR /workspace/iam-enforcement-svc
RUN --mount=type=cache,target=/root/.gradle gradle bootJar --no-daemon

FROM eclipse-temurin:21-jre
# curl+jq: AppRole login and PKI cert issuance against OpenBao at startup.
# openssl: bundles the issued PEM cert/key into a PKCS12 keystore. keytool
# (already part of the JRE) builds the matching truststore. See
# mtls-entrypoint.sh and docs/DECISIONS.md, mTLS rollout entry.
RUN apt-get update && apt-get install -y --no-install-recommends curl jq openssl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /workspace/iam-enforcement-svc/build/libs/*.jar app.jar
COPY mtls-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENV SERVICE_CN=iam-enforcement-svc
EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
