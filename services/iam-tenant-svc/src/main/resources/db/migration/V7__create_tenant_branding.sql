-- Per-tenant login-page branding (FR-6.1): color scheme, logo and a headline.
-- One optional row per tenant; no row means the platform's default theme.
-- Everything here is public by design -- it is rendered on the pre-login page --
-- so nothing secret may ever be stored in this table.
CREATE TABLE tenant_branding (
    tenant_id      UUID PRIMARY KEY,
    primary_color  VARCHAR(7),
    logo_url       VARCHAR(1024),
    headline       VARCHAR(120),
    default_theme  VARCHAR(8),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
