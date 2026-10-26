#!/usr/bin/env bash
# Runs automatically on every VM boot (installed as a GCE instance
# startup-script) -- OpenBao's raft storage persists across restarts, but
# the seal state does NOT: a freshly (re)started OpenBao process always
# comes back sealed, regardless of prior unseal history (that's the whole
# point of a Shamir seal -- the master key isn't stored anywhere). This
# also means EVERY dependent service's AppRole secret_id needs to be
# re-minted and picked up fresh after each unseal, since restarting an
# existing container in place does NOT re-read the current .env.
#
# Deliberately does NOT try to bash-parse `bao status` output to decide
# whether to unseal -- an earlier version of this script did that and the
# fragile shell JSON parsing produced a wrong "already unsealed" result on
# its very first real run. bootstrap.py's own Python-based seal check
# (verified reliable many times over) is what actually decides; this
# script just always calls it.
set -euo pipefail

REPO=/opt/iam/Iam_core_Platform
LOG=/var/log/iam-unseal-on-boot.log
exec >>"$LOG" 2>&1
echo "=== $(date -u) unseal-on-boot starting ==="

cd "$REPO"

echo "Waiting for Docker to be ready..."
for i in $(seq 1 30); do
  docker info >/dev/null 2>&1 && break || true
  sleep 2
done

echo "Bringing up infra tier..."
docker compose up -d postgres valkey openbao kafka-1 kafka-2 kafka-3

echo "Waiting for OpenBao to be reachable..."
for i in $(seq 1 30); do
  rc=0
  # `|| rc=$?` is load-bearing, not decoration: under `set -e`, a bare failing
  # command not otherwise protected kills the whole script immediately -- hit
  # this live (script silently died here on `bao status`'s expected exit 2).
  docker compose exec -T openbao bao status -address=http://127.0.0.1:8200 >/dev/null 2>&1 || rc=$?
  # exit 0 = unsealed, exit 2 = sealed-but-reachable -- both mean "ready to talk to".
  if [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]; then break; fi
  sleep 2
done

echo "Ensuring OpenBao is unsealed and AppRole credentials are fresh..."
docker run --rm --network=iam_core_platform_default -e BAO_ADDR=http://openbao:8200 \
  -v "$REPO:/repo" -w /repo/infra/openbao python:3.11-slim python3 bootstrap.py

echo "Bringing up the rest of the stack..."
# Everything else (login-portal, admin-console, jaeger, whoami, iam-audit-svc)
# doesn't use AppRole at all, so a plain "up -d" (no recreate) is fine for them.
docker compose up -d

echo "Force-recreating the AppRole-dependent services so they pick up the fresh secret_id (a plain restart keeps whatever was baked in at the container's original creation time, not the current .env) -- deliberately excludes postgres/valkey/kafka/openbao, which must NOT be recreated again here or OpenBao reseals immediately after the unseal above."
docker compose up -d --force-recreate \
  iam-tenant-svc iam-geo-svc iam-identity-svc iam-policy-svc iam-session-svc \
  iam-device-svc iam-auth-svc iam-enforcement-svc iam-oidcprovider-svc

echo "=== $(date -u) unseal-on-boot finished ==="
