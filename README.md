# iam-platform-docs

Umbrella documentation repo for the enterprise IAM platform (multi-tenant
SaaS, comparable in scope to Okta/Entra ID). This repo holds the
platform-wide product/architecture package; each service's own code lives
in its own repo per `CLAUDE.md`'s polyrepo model.

## Contents

| File | Purpose |
|---|---|
| `CLAUDE.md` | Architecture principles (AP-1–AP-8), tech stack, repo list, build order |
| `docs/BRD.md` | Business Requirements Document — full numbered FR/NFR set |
| `docs/ENGINEERING_GUARDRAILS.md` | Tier 1/2/3 decision framework, error-handling standard, audit schema, Definition of Done |
| `docs/DECISIONS.md` | Log of Tier-2/Tier-3 architectural decisions made per module, with rationale and FR references |
| `docs/OPEN_QUESTIONS.md` | Tier-3 items awaiting human input — must be empty before a module is marked done |
| `docs/specs/` | Per-module specs (data schema, API surface, audit events, error handling, success criteria), written before implementation per the CLAUDE.md workflow |

## Status

- **Module 1 (Directory & Identity Sourcing + Authentication Policy Engine):** spec complete (`docs/specs/directory-auth-SPEC.md`), implemented in `iam-core-platform`. Not yet compiled/executed against real infrastructure.
- **Module 2 (Contextual Access Control + PEP):** not started — next in build order per `CLAUDE.md`.

## Workflow

Per `CLAUDE.md`, every module follows: structured decision interview →
`docs/DECISIONS.md` entry → `docs/specs/<module>-SPEC.md` → implementation
in that module's own repo → tests. `docs/OPEN_QUESTIONS.md` must be empty
before a module is considered done.
