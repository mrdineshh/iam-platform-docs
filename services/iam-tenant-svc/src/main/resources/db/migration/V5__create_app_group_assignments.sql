-- Which groups (iam-identity-svc's groups.id, same cross-service
-- by-convention reference iam-policy-svc's policies.scope_id already uses
-- for OU) are allowed to see and launch a given app on "My Apps". An app
-- with zero rows here is visible to nobody except ADMIN users, who always
-- see every connected app regardless of group (BRD decision, 2026-10-23).
CREATE TABLE oidc_client_groups (
    id             UUID PRIMARY KEY,
    oidc_client_id UUID NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
    group_id       UUID NOT NULL
);
CREATE UNIQUE INDEX idx_oidc_client_groups_unique ON oidc_client_groups (oidc_client_id, group_id);
CREATE INDEX idx_oidc_client_groups_group_id ON oidc_client_groups (group_id);

CREATE TABLE saml_sp_groups (
    id         UUID PRIMARY KEY,
    saml_sp_id UUID NOT NULL REFERENCES saml_sps(id) ON DELETE CASCADE,
    group_id   UUID NOT NULL
);
CREATE UNIQUE INDEX idx_saml_sp_groups_unique ON saml_sp_groups (saml_sp_id, group_id);
CREATE INDEX idx_saml_sp_groups_group_id ON saml_sp_groups (group_id);
