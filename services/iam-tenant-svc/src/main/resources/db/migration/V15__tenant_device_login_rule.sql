-- Platform-level sign-in rule (docs/DECISIONS.md, 2026-11-19 sign-in rule entry): when on, non-admin users can only
-- sign in from an approved, compliant laptop. One row per tenant; no row means the rule is off (the default).
CREATE TABLE tenant_device_login_rule (
    tenant_id              UUID         PRIMARY KEY,
    require_trusted_device BOOLEAN      NOT NULL DEFAULT FALSE,
    updated_at             TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_by             VARCHAR(64)  NULL
);
