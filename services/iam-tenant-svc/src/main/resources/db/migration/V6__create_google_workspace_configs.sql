-- Per-tenant Google Workspace auto-provisioning config. The service
-- account's own private key is deliberately NOT stored here -- it's
-- OpenBao-held (path "google-workspace/<tenant_id>"), same as every other
-- credential in this system. This table only holds what's needed to know
-- *whether* a tenant has the integration configured and where new users
-- should land.
CREATE TABLE google_workspace_configs (
    id             UUID PRIMARY KEY,
    tenant_id      UUID NOT NULL UNIQUE,
    domain         VARCHAR(255) NOT NULL,
    admin_email    VARCHAR(255) NOT NULL,
    org_unit_path  VARCHAR(255),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
