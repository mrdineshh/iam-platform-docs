-- Device-bound sign-in (docs/specs/device-bound-signin-SPEC.md).
ALTER TABLE oidc_clients ADD COLUMN require_trusted_device BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE saml_sps ADD COLUMN require_trusted_device BOOLEAN NOT NULL DEFAULT FALSE;

-- One-time challenges the agent signs to prove a sign-in comes from an enrolled laptop. Short lived (60 s) and
-- single use; consumed_at is set atomically on first use, even when verification then fails.
CREATE TABLE iam_device_login_challenges (
    id          UUID PRIMARY KEY,
    tenant_id   UUID        NOT NULL,
    nonce       TEXT        NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_device_login_challenges_expires ON iam_device_login_challenges (expires_at);
