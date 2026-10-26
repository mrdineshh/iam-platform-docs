CREATE TABLE users (
    id           UUID PRIMARY KEY,
    tenant_id    UUID NOT NULL,
    email        VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    status       VARCHAR(16) NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX idx_users_tenant_email ON users (tenant_id, email);
CREATE INDEX idx_users_tenant_id ON users (tenant_id);
