#!/usr/bin/env bash
# Deploy one or more IAM services to the demo VM: package the source, copy it over, back up the
# current copy, rebuild the Docker image ON THE VM and restart just that container.
#
#   ./scripts/deploy-vm.sh iam-admin-console
#   ./scripts/deploy-vm.sh iam-session-svc iam-auth-svc iam-login-portal   # order matters, see below
#   ./scripts/deploy-vm.sh --dry-run iam-geo-svc                            # show what would happen
#   ./scripts/deploy-vm.sh --list                                           # known services
#
# Needs: gcloud (logged in, with SSH access to the VM), tar. Run from anywhere in the repo.
# Override the target with IAM_PROJECT, IAM_ZONE, IAM_VM, IAM_VM_DIR if it ever moves.
#
# Order: when a change touches several services, deploy the one that RECEIVES new fields first
# (e.g. iam-session-svc before iam-auth-svc). See docs/DEPLOYMENT.md.
set -euo pipefail

PROJECT="${IAM_PROJECT:-testing-ratnesh}"
ZONE="${IAM_ZONE:-us-central1-a}"
VM="${IAM_VM:-iam-platform-demo}"
VM_DIR="${IAM_VM_DIR:-/opt/iam/Iam_core_Platform}"

KNOWN="iam-audit-svc iam-tenant-svc iam-geo-svc iam-identity-svc iam-policy-svc iam-session-svc iam-device-svc iam-auth-svc iam-enforcement-svc iam-oidcprovider-svc iam-login-portal iam-admin-console"

dry=0
services=()
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry=1 ;;
    --list) echo "$KNOWN" | tr ' ' '\n'; exit 0 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    -*) echo "unknown option: $arg" >&2; exit 2 ;;
    *) services+=("$arg") ;;
  esac
done

[ ${#services[@]} -gt 0 ] || { echo "usage: $0 [--dry-run] <service>..."; echo "known: $KNOWN"; exit 2; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for s in "${services[@]}"; do
  case " $KNOWN " in *" $s "*) ;; *) echo "unknown service: $s (try --list)" >&2; exit 2 ;; esac
  [ -d "$ROOT/services/$s" ] || { echo "missing folder services/$s" >&2; exit 2; }
done

# Never ship a half-edited tree by accident: warn (not block) when the work tree has uncommitted changes.
if [ -n "$(git -C "$ROOT" status --porcelain -- services 2>/dev/null)" ]; then
  echo "NOTE: services/ has uncommitted changes -- what you deploy is your working copy, not a commit."
fi

echo "Target: $VM ($ZONE, project $PROJECT), directory $VM_DIR"
echo "Services, in order: ${services[*]}"
if [ "$dry" = 1 ]; then echo "(dry run: nothing copied or restarted)"; exit 0; fi

TGZ="$(mktemp -t iam-deploy-XXXXXX).tgz"
trap 'rm -f "$TGZ"' EXIT
( cd "$ROOT/services" && tar \
    --exclude=node_modules --exclude=.next --exclude=dist --exclude=build \
    --exclude=.gradle --exclude=tsconfig.tsbuildinfo \
    -czf "$TGZ" "${services[@]}" )
echo "Packaged $(du -h "$TGZ" | cut -f1)"

REMOTE_TGZ="/tmp/iam-deploy-$$.tgz"
gcloud compute scp "$TGZ" "$VM:$REMOTE_TGZ" --zone "$ZONE" --project "$PROJECT" >/dev/null

# Runs on the VM. Each service: back up the current source (for rollback), extract, build, restart.
REMOTE_SCRIPT='
set -euo pipefail
cd "'"$VM_DIR"'"
ts=$(date +%s)
for s in '"${services[*]}"'; do
  sudo cp -a "services/$s" "/tmp/$s.bak.$ts"
done
sudo tar -xzf "'"$REMOTE_TGZ"'" -C services
for s in '"${services[*]}"'; do
  echo "=== build $s"
  sudo docker compose build "$s" 2>&1 | tail -3
  echo "=== restart $s"
  sudo docker compose up -d --no-deps "$s" 2>&1 | tail -2
done
rm -f "'"$REMOTE_TGZ"'"
echo "=== status"
sudo docker compose ps --format "{{.Name}}  {{.Status}}" | grep -E "'"$(IFS='|'; echo "${services[*]}")"'"
echo "Backups: /tmp/<service>.bak.$ts (rollback: see docs/DEPLOYMENT.md)"
'
gcloud compute ssh "$VM" --zone "$ZONE" --project "$PROJECT" --command "bash -c $(printf '%q' "$REMOTE_SCRIPT")"

echo
echo "Done. Kotlin services take ~30-60s to finish starting; a 502 from the site in that window is normal."
