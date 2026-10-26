CREATE TABLE saml_sps (
    id            UUID PRIMARY KEY,
    tenant_id     UUID NOT NULL,
    name          VARCHAR(255) NOT NULL,
    sp_entity_id  VARCHAR(512) NOT NULL,
    acs_url       VARCHAR(1024) NOT NULL,
    launch_url    VARCHAR(1024),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Entity IDs are meant to be globally unique per the SAML spec, and
-- iam-oidcprovider-svc resolves an incoming AuthnRequest's Issuer straight
-- to a single SP registration by this value alone (not tenant-scoped --
-- the request carries no other tenant context at that point).
CREATE UNIQUE INDEX idx_saml_sps_entity_id ON saml_sps (sp_entity_id);
CREATE INDEX idx_saml_sps_tenant_id ON saml_sps (tenant_id);
