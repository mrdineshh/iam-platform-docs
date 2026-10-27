-- Outbound user provisioning (SCIM 2.0): the platform pushes user lifecycle
-- changes (create, suspend, reactivate, delete) to integrated apps.
--
-- scim_connections: one optional SCIM endpoint per connected app. The bearer
-- token is NOT stored here; it lives in OpenBao at scim/<id>, like every other
-- credential in this system.
CREATE TABLE scim_connections (
    id          UUID PRIMARY KEY,
    tenant_id   UUID         NOT NULL,
    app_kind    VARCHAR(16)  NOT NULL,   -- 'OIDC' or 'SAML'
    app_id      UUID         NOT NULL,
    base_url    VARCHAR(1024) NOT NULL,
    enabled     BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_scim_connection_app UNIQUE (tenant_id, app_kind, app_id)
);

CREATE INDEX idx_scim_connections_tenant ON scim_connections (tenant_id);

-- provisioned_accounts: the app-side account we created (or adopted) for a
-- platform user, so a later suspend or delete can address it by the app's own
-- resource id. Only accounts listed here are ever modified or deleted.
--   state: PENDING (never created yet), ACTIVE, SUSPENDED
--   last_error: set when the most recent attempt failed, cleared on success
CREATE TABLE provisioned_accounts (
    id             UUID PRIMARY KEY,
    tenant_id      UUID         NOT NULL,
    user_id        UUID         NOT NULL,
    connection_id  UUID         NOT NULL REFERENCES scim_connections (id) ON DELETE CASCADE,
    external_id    VARCHAR(255),
    state          VARCHAR(16)  NOT NULL,
    last_error     TEXT,
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_provisioned_user_connection UNIQUE (user_id, connection_id)
);

CREATE INDEX idx_provisioned_accounts_user ON provisioned_accounts (user_id);
