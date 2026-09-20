#!/bin/sh
# Shared mTLS bootstrap for every backend service's container entrypoint.
# Authenticates to OpenBao via AppRole (never the root token -- see
# infra/openbao/bootstrap.py), issues this service its own short-lived
# internal certificate, bundles it into a PKCS12 keystore/truststore (so
# Spring Boot's spring.ssl.bundle and the JDK's own SSLContext APIs can
# both consume it with zero extra crypto library dependencies), and
# exports the same OpenBao client token as BAO_TOKEN for the existing KV
# secret reads (password pepper, TOTP DEKs, OIDC signing key) that already
# expected that env var. See docs/DECISIONS.md, mTLS rollout entry.
set -e

BAO_ADDR="${BAO_ADDR:-http://openbao:8200}"
: "${SERVICE_CN:?SERVICE_CN must be set (the docker-compose service name / PKI common name)}"
: "${BAO_APPROLE_ROLE_ID:?BAO_APPROLE_ROLE_ID must be set}"
: "${BAO_APPROLE_SECRET_ID:?BAO_APPROLE_SECRET_ID must be set}"
MTLS_DIR=/mtls
mkdir -p "$MTLS_DIR"

echo "[mtls-entrypoint] authenticating to OpenBao via AppRole..."
LOGIN_RESP=$(curl -sf -X POST "$BAO_ADDR/v1/auth/approle/login" \
  -H 'Content-Type: application/json' \
  -d "{\"role_id\":\"${BAO_APPROLE_ROLE_ID}\",\"secret_id\":\"${BAO_APPROLE_SECRET_ID}\"}")
CLIENT_TOKEN=$(printf '%s' "$LOGIN_RESP" | jq -r '.auth.client_token')
if [ -z "$CLIENT_TOKEN" ] || [ "$CLIENT_TOKEN" = "null" ]; then
  printf '[mtls-entrypoint] AppRole login failed: %s\n' "$LOGIN_RESP" >&2
  exit 1
fi

echo "[mtls-entrypoint] issuing certificate for CN=$SERVICE_CN..."
ISSUE_RESP=$(curl -sf -X PUT "$BAO_ADDR/v1/pki/issue/internal-services" \
  -H "X-Vault-Token: $CLIENT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"common_name\":\"$SERVICE_CN\",\"ttl\":\"720h\"}")

printf '%s' "$ISSUE_RESP" | jq -r '.data.certificate' > "$MTLS_DIR/cert.pem"
printf '%s' "$ISSUE_RESP" | jq -r '.data.private_key' > "$MTLS_DIR/key.pem"
printf '%s' "$ISSUE_RESP" | jq -r '.data.issuing_ca' > "$MTLS_DIR/ca.pem"

if [ ! -s "$MTLS_DIR/cert.pem" ] || [ ! -s "$MTLS_DIR/key.pem" ] || [ "$(cat "$MTLS_DIR/cert.pem")" = "null" ]; then
  printf '[mtls-entrypoint] cert issuance failed: %s\n' "$ISSUE_RESP" >&2
  exit 1
fi

rm -f "$MTLS_DIR/keystore.p12" "$MTLS_DIR/truststore.p12"

openssl pkcs12 -export \
  -in "$MTLS_DIR/cert.pem" -inkey "$MTLS_DIR/key.pem" \
  -name mtls -out "$MTLS_DIR/keystore.p12" -passout pass:changeit

keytool -importcert -noprompt \
  -alias internal-ca -file "$MTLS_DIR/ca.pem" \
  -keystore "$MTLS_DIR/truststore.p12" -storetype PKCS12 -storepass changeit

echo "[mtls-entrypoint] certificate ready for $SERVICE_CN."
export BAO_TOKEN="$CLIENT_TOKEN"

exec java -Duser.timezone=UTC -jar app.jar
