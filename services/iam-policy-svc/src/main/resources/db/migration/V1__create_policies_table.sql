CREATE TABLE policies (
    id                           UUID PRIMARY KEY,
    tenant_id                    UUID NOT NULL,
    scope                        VARCHAR(16) NOT NULL,
    scope_id                     UUID NOT NULL,
    allowed_countries            TEXT,
    allowed_countries_hard_cap   BOOLEAN NOT NULL DEFAULT FALSE,
    blocked_countries            TEXT,
    blocked_countries_hard_cap   BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at                   TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX idx_policies_tenant_scope_scopeid ON policies (tenant_id, scope, scope_id);
