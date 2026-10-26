CREATE TABLE oidc_clients (
    id                 UUID PRIMARY KEY,
    tenant_id          UUID NOT NULL,
    name               VARCHAR(255) NOT NULL,
    client_secret_hash TEXT NOT NULL,
    redirect_uris      TEXT NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_oidc_clients_tenant_id ON oidc_clients (tenant_id);
