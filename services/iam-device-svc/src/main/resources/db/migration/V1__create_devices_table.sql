CREATE TABLE devices (
    id                       UUID PRIMARY KEY,
    tenant_id                UUID NOT NULL,
    user_id                  UUID NOT NULL,
    status                   VARCHAR(16) NOT NULL,
    totp_secret_ciphertext   BYTEA NOT NULL,
    totp_secret_nonce        BYTEA NOT NULL,
    fcm_token                TEXT,
    failed_totp_attempts     INT NOT NULL DEFAULT 0,
    locked_until             TIMESTAMPTZ,
    created_at               TIMESTAMPTZ NOT NULL,
    updated_at               TIMESTAMPTZ NOT NULL
);

-- Lookup pattern is always "the most recent device for this tenant/user"
-- (one device, both factors -- re-enrolling replaces which row is "current").
CREATE INDEX idx_devices_tenant_user_created ON devices (tenant_id, user_id, created_at DESC);
