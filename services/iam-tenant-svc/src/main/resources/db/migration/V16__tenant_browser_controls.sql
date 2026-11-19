-- Tenant-wide browser controls switched from the Admin Console and applied by the endpoint agent
-- (docs/DECISIONS.md, 2026-11-19). No row means every control is off (the default).
CREATE TABLE tenant_browser_controls (
    tenant_id                UUID         PRIMARY KEY,
    block_personal_microsoft BOOLEAN      NOT NULL DEFAULT FALSE,
    updated_at               TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_by               VARCHAR(64)  NULL
);
