CREATE TABLE tenants (
    id          UUID PRIMARY KEY,
    name        VARCHAR(255) NOT NULL,
    subdomain   VARCHAR(63) NOT NULL,
    status      VARCHAR(16) NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX idx_tenants_subdomain ON tenants (subdomain);
