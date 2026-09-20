# Real OpenBao server mode -- replaces the "-dev" ephemeral mode that has
# repeatedly wiped the password pepper, TOTP DEKs, and OIDC signing key on
# every Docker Desktop restart (see docs/DECISIONS.md, multiple entries).
# Raft integrated storage persists to a Docker volume (see docker-compose.yml)
# so the CA, PKI roles, AppRole credentials, and KV secrets all survive a
# container/daemon restart from here on.

storage "raft" {
  # Reuses the image's own pre-owned /openbao/file directory (uid 100 /
  # gid 1000) -- a fresh path here gets created root-owned by Docker when
  # the named volume first mounts, which the non-root "openbao" user in
  # this image can't write to.
  path    = "/openbao/file"
  node_id = "node1"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  # TLS to OpenBao itself is a real-deployment concern (layered on with the
  # actual ingress/gateway work) -- this listener sits on the same trusted
  # Docker network every service already reaches Postgres/Valkey/Kafka on
  # unencrypted. Not a new gap introduced here.
  tls_disable = "true"
}

api_addr     = "http://openbao:8200"
cluster_addr = "http://openbao:8201"

ui = true
