# Deployment and team handover

How the IAM platform is deployed today, how to deploy a change, and what to watch out for. Written so a
new team member can ship a change without asking. **No secrets are in this file** -- see "Access and secrets".

Companion docs: `docs/INTERNALS.md` (how every service works), `docs/DECISIONS.md` (why things are the way
they are), `CLAUDE.md` (architecture rules AP-1 to AP-8 -- read before changing anything structural).

---

## 1. What runs where

| Part | Where | Notes |
|---|---|---|
| IAM platform (all services) | One GCE VM, `iam-platform-demo`, zone `us-central1-a`, project `testing-ratnesh` | Docker Compose, directory `/opt/iam/Iam_core_Platform` (NOT a git repo) |
| Public entry | Caddy on the VM, config `/etc/caddy/Caddyfile` | Terminates HTTPS, forwards to the containers on localhost |
| Pulse (the task app) | Google Cloud Run, same project | Separate repo `pulse-dev`, see section 8 |

Public addresses (all `https`, host `34-71-129-0.sslip.io`):

| Address | Service |
|---|---|
| `admin.` | admin console (React) |
| `login.` | user portal and launchpad (Next.js) |
| `oidc.` | OpenID Connect / SAML provider |
| `auth.` `tenant.` `policy.` `gateway.` | backend APIs used by the browser apps |

The demo tenant is `econz`. Sign-in page: `https://login.34-71-129-0.sslip.io/portal`.

### The VM is on a schedule

The VM is stopped and started automatically (gcloud operation history shows the `devops` service account
stopping it around 06:30 and starting it around 21:00). While it is stopped every site is down and
`gcloud compute ssh/scp` time out. Check first:

```
gcloud compute instances describe iam-platform-demo --zone us-central1-a --project testing-ratnesh --format="value(status)"
```

Start it manually only if you really need it (`gcloud compute instances start ...`), and expect the schedule to
stop it again. After any start, OpenBao may come back **sealed** (see section 6) and services that need
certificates will not start until it is unsealed.

---

## 2. Access and secrets

You need:
- **GitHub** access to the repo, branch **`dev`**. Work on `dev`; do not push to `main` without agreement.
- **Google Cloud** access to project `testing-ratnesh` with permission to SSH to the VM
  (`gcloud compute ssh`, via OS Login or the project's SSH metadata). Ask the project owner to grant it.
- On the VM you are user `devops`; Docker needs `sudo`.

Secrets are **never in git** and must be shared through a password manager, not chat or email:
- OpenBao unseal key and root token: `infra/openbao/secrets/init.json` on the VM (gitignored).
- Pulse's SCIM token and any Google service-account key.
- `.env` on the VM holds the real configuration (gitignored).

If you find a secret in the repo, rotate it first and tell the owner.

---

## 3. Deploy a change (the normal way)

1. Make the change on `dev`, run the tests (section 4), commit and push.
2. Make sure the VM is running (section 1).
3. From the repo root:

```
./scripts/deploy-vm.sh iam-admin-console
./scripts/deploy-vm.sh iam-session-svc iam-auth-svc     # several services, deployed in this order
./scripts/deploy-vm.sh --dry-run iam-geo-svc            # preview only
./scripts/deploy-vm.sh --list                           # service names
```

The script packages the service folder(s), copies them to the VM, backs up the current source to
`/tmp/<service>.bak.<timestamp>`, rebuilds the Docker image **on the VM**, restarts only that container
and prints its status. There is no CI/CD pipeline yet: what you deploy is your working copy, not a commit.

4. Verify: open the site with a hard refresh (Ctrl+Shift+R). Kotlin services take 30-60 seconds to start, so a
   502 right after deploying is normal.

**Order matters** when a change adds a field that one service sends and another receives: deploy the receiver
first (`iam-session-svc` before `iam-auth-svc`, `iam-tenant-svc` before the admin console).

**Rollback:**
```
gcloud compute ssh iam-platform-demo --zone us-central1-a --project testing-ratnesh
cd /opt/iam/Iam_core_Platform
sudo rm -rf services/<service> && sudo cp -a /tmp/<service>.bak.<timestamp> services/<service>
sudo docker compose build <service> && sudo docker compose up -d --no-deps <service>
```
Backups in `/tmp` disappear on reboot; copy one elsewhere if you need it to last.

---

## 4. Tests and local checks

- **Frontends** (`services/iam-admin-console`, `services/iam-login-portal`): `npm ci`, then `npx tsc --noEmit -p .`,
  `npx vite build` (admin console) or `npx next build` (portal), and `npx vitest run` where tests exist.
- **Kotlin services:** there may be no JDK on your machine. Either install JDK 21 and run `./gradlew test` in the service
  folder, or run the tests on the VM in a throwaway container:
  ```
  sudo docker run --rm -v /tmp/gtest:/workspace -v /tmp/gradle-home:/home/gradle/.gradle \
    -w /workspace/<service> gradle:9.7.1-jdk21 gradle test --no-daemon
  ```
  (copy `iam-service-kit` and the service folder into `/tmp/gtest` first). Read the result XML under
  `build/test-results/test/` -- a quiet run does not by itself prove the tests passed.
- The Docker build runs `gradle bootJar` only; **it does not run the tests**, so run them yourself.

---

## 5. Where the configuration lives

- `docker-compose.yml` in the repo is the reference, but the VM's copy is live-patched and can differ. Compare
  before replacing it, and back it up first.
- The admin console's service URLs are **baked in at build time** from `ADMIN_CONSOLE_*` values in the VM's `.env`.
  Changing a URL means rebuilding that image.
- `LOGIN_PORTAL_DEFAULT_TENANT` (set to `econz` on the VM) lets the portal work without a tenant in the address.
  Leave it empty on a real multi-tenant deployment.
- The geo service image downloads the DB-IP City Lite database at build time. The month is a build argument in
  `services/iam-geo-svc/Dockerfile` (`DBIP_MONTH`); update it about monthly. Licence CC BY 4.0, credit DB-IP.

---

## 6. Things that will bite you

- **OpenBao seals itself on restart.** Until it is unsealed, services cannot get their certificates. Use
  `infra/openbao/bootstrap.py` and the unseal key from the password manager. If a new secret path is needed
  (for example `secret/data/scim/*`) it must also be in the policy in that script **and** applied on the server.
- **Raw service ports are publicly open.** The firewall rule `allow-iam-platform-demo` exposes 8082, 8085, 8087,
  8089, 8090, 5173, 3001, 3002 to the internet, so the proxy can be bypassed. Only 80 and 443 should be public.
  This undermines the server-side IP detection (`docs/DECISIONS.md`, 2026-10-29). Fix pending.
- **Token issuer is `http://localhost:8090`** (compose `OIDC_ISSUER`). Apps get discovery documents and tokens with
  that issuer; Pulse works around it with its own `OIDC_JWKS_URI` setting. Changing it also changes the SAML entity
  ID, so decide deliberately.
- Windows users: the repo has mixed line endings; do not reformat whole files.

---

## 7. Known gaps and ideas (roughly by priority)

1. Close the raw ports in the firewall.
2. A CI pipeline: run tests and builds on every push to `dev`, then deploy changed services automatically.
3. Alerts and extra checks for sign-ins from a new country, city or device (the data is already recorded).
4. An audit-log page in the admin console with search and export.
5. Finer admin roles (today there are only Admin and User; every Admin can do everything).
6. Passkeys (WebAuthn), self-service password reset, directory sync from Entra ID or Active Directory.
7. Map IAM groups to Pulse roles and departments through SCIM (today SCIM-created Pulse users get a default role).
8. Remove the single point of failure (one VM) and add monitoring.

---

## 8. Pulse (separate repo `pulse-dev`)

- NestJS API plus a React web app, own git repo, branch `main`. It is **not** part of this repo.
- Runs on Cloud Run: services `taskapp-api` and `taskapp-web` in `us-central1`, project `testing-ratnesh`; infrastructure is
  Terraform in `pulse-dev/infra/environments/dev` (state in the GCS bucket `testing-ratnesh-tfstate`).
- Images are built with Cloud Build into `us-central1-docker.pkg.dev/testing-ratnesh/taskapp/`. The repo's own
  `cloudbuild.yaml` files point at an old project; use a config that targets `testing-ratnesh`.
- **Terraform caution:** apply with `-target` only. A full `apply` can blank live secret versions or settings whose
  values are not in `terraform.tfvars`. Read the plan before applying.
- Pulse has its own database (Cloud SQL `taskapp-dev`). IAM only authenticates; users are matched by email.
- Pulse is a SCIM server at `/api/v1/scim/v2`; IAM connects to it from the Applications page.
