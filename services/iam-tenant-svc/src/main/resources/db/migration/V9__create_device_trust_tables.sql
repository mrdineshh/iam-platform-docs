-- Endpoint Device Trust (IAM Endpoint Device Trust Technical Specification v1,
-- Phase 1, Windows-only). Schema matches the spec's Section 11 proposed model;
-- platform-agnostic even though the agent itself ships Windows-only first.
--
-- iam_devices is the authoritative device record (Section 4 "Device Registry").
-- Private keys are never stored here (Section 11) -- only the device's PUBLIC
-- key lives in iam_device_keys; the matching private key never leaves the
-- endpoint (TPM/CNG-backed where available).
CREATE TABLE iam_devices (
    id                  UUID PRIMARY KEY,
    tenant_id           UUID         NOT NULL,
    user_id             UUID         NOT NULL,
    device_instance_id  UUID         NOT NULL,  -- agent-generated, stable across re-enrolment attempts
    platform            VARCHAR(16)  NOT NULL,  -- WINDOWS (only supported value in Phase 1)
    hostname            VARCHAR(255),
    ownership           VARCHAR(16)  NOT NULL,  -- CORPORATE or BYOD
    lifecycle_status    VARCHAR(24)  NOT NULL,  -- see DeviceLifecycleStatus
    agent_version       VARCHAR(32),
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_seen_at        TIMESTAMPTZ,
    CONSTRAINT uq_iam_devices_tenant_instance UNIQUE (tenant_id, device_instance_id)
);

CREATE INDEX idx_iam_devices_tenant ON iam_devices (tenant_id);
CREATE INDEX idx_iam_devices_user ON iam_devices (tenant_id, user_id);
CREATE INDEX idx_iam_devices_status ON iam_devices (tenant_id, lifecycle_status);

-- Supplementary correlation only (Section 5) -- never sufficient authentication
-- on its own. Raw serial/hardware UUID are not stored (Section 11); only a
-- salted, keyed hash, so values can be matched without being recoverable.
CREATE TABLE iam_device_hardware (
    device_id            UUID PRIMARY KEY REFERENCES iam_devices (id) ON DELETE CASCADE,
    fingerprint_version   INTEGER      NOT NULL,
    fingerprint_hash      VARCHAR(128) NOT NULL,
    hardware_uuid_hash    VARCHAR(128),
    serial_hash           VARCHAR(128),
    manufacturer          VARCHAR(255),
    model                 VARCHAR(255),
    os_version             VARCHAR(255)
);

-- One row per key generation the device has used (rotation keeps history).
-- assurance_level distinguishes a TPM/CNG-protected key from a software
-- fallback (Section 5.3) -- the PEP / admin console must be able to show this.
CREATE TABLE iam_device_keys (
    id              UUID PRIMARY KEY,
    device_id       UUID         NOT NULL REFERENCES iam_devices (id) ON DELETE CASCADE,
    public_key      TEXT         NOT NULL,
    key_algorithm   VARCHAR(32)  NOT NULL,  -- e.g. RSA2048, ECDSA_P256, ED25519
    assurance_level VARCHAR(24)  NOT NULL,  -- HARDWARE_TPM, HARDWARE_CNG, SOFTWARE
    status          VARCHAR(16)  NOT NULL,  -- ACTIVE, ROTATED, REVOKED
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    rotated_at      TIMESTAMPTZ
);

CREATE INDEX idx_iam_device_keys_device ON iam_device_keys (device_id, status);

-- One row per certificate issued against a device key. Issued by OpenBao's
-- PKI secrets engine (Section 16 "PKI: OpenBao-backed CA/key custody") --
-- this table mirrors OpenBao's own record, it is not itself the source of
-- truth for revocation (OpenBao's CRL/OCSP is); it exists so the admin
-- console and PEP can query certificate state without calling OpenBao on
-- every request.
CREATE TABLE iam_device_certificates (
    id              UUID PRIMARY KEY,
    device_id       UUID         NOT NULL REFERENCES iam_devices (id) ON DELETE CASCADE,
    key_id          UUID         NOT NULL REFERENCES iam_device_keys (id),
    issuer_key_id   VARCHAR(255) NOT NULL,  -- OpenBao PKI mount/role that issued it
    serial_number   VARCHAR(255) NOT NULL,
    fingerprint     VARCHAR(128) NOT NULL,
    not_before      TIMESTAMPTZ  NOT NULL,
    not_after       TIMESTAMPTZ  NOT NULL,
    status          VARCHAR(16)  NOT NULL,  -- ACTIVE, EXPIRED, REVOKED
    revoked_at      TIMESTAMPTZ,
    revoked_reason  VARCHAR(255),
    CONSTRAINT uq_iam_device_certificates_serial UNIQUE (serial_number)
);

CREATE INDEX idx_iam_device_certificates_device ON iam_device_certificates (device_id, status);

-- Every approve/reject/suspend/revoke decision -- Section 6.3 "Approval/
-- rejection actions require role-based authorization, reason capture and
-- audit." This table IS that record; AuditPublisher also emits the generic
-- platform audit event for the same action (Guardrails Section 5 minimum
-- schema), so the two must stay consistent, not duplicated as the source
-- of truth.
CREATE TABLE iam_device_approvals (
    id              UUID PRIMARY KEY,
    device_id       UUID         NOT NULL REFERENCES iam_devices (id) ON DELETE CASCADE,
    approval_mode   VARCHAR(16)  NOT NULL,  -- AUTOMATIC or MANUAL
    decision        VARCHAR(16)  NOT NULL,  -- APPROVED, REJECTED, SUSPENDED, REVOKED
    actor_id        VARCHAR(255) NOT NULL,  -- admin user id, or "system" for automatic
    reason          TEXT,
    decided_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_iam_device_approvals_device ON iam_device_approvals (device_id, decided_at DESC);

CREATE TABLE iam_device_posture (
    device_id       UUID PRIMARY KEY REFERENCES iam_devices (id) ON DELETE CASCADE,
    posture_status  VARCHAR(16)  NOT NULL,  -- COMPLIANT, NON_COMPLIANT, UNKNOWN
    risk_score      INTEGER,
    signals_json    TEXT,
    evaluated_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE iam_device_heartbeats (
    device_id       UUID PRIMARY KEY REFERENCES iam_devices (id) ON DELETE CASCADE,
    last_seen_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    agent_version   VARCHAR(32)  NOT NULL,
    policy_version  INTEGER      NOT NULL,
    health_status   VARCHAR(16)  NOT NULL  -- HEALTHY, DEGRADED, TAMPERED
);

CREATE TABLE iam_device_events (
    id              UUID PRIMARY KEY,
    tenant_id       UUID         NOT NULL,
    device_id       UUID         NOT NULL REFERENCES iam_devices (id) ON DELETE CASCADE,
    event_type      VARCHAR(64)  NOT NULL,
    severity        VARCHAR(16)  NOT NULL,  -- INFO, WARNING, CRITICAL
    metadata_json   TEXT,
    occurred_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_iam_device_events_device ON iam_device_events (device_id, occurred_at DESC);
CREATE INDEX idx_iam_device_events_tenant ON iam_device_events (tenant_id, occurred_at DESC);

-- Tenant-level device trust policy (Section 13.3). One ACTIVE row per
-- tenant at a time; configuration_json holds approval rules, max devices
-- per user, heartbeat/posture intervals, failure mode, etc. -- this is
-- deliberately a JSON blob here (same pragmatic choice iam-policy-svc makes
-- for its own policy documents) rather than one column per setting, since
-- the field set is still evolving through Phase 1/2/3.
CREATE TABLE iam_device_policies (
    id                UUID PRIMARY KEY,
    tenant_id         UUID         NOT NULL,
    name              VARCHAR(255) NOT NULL,
    version           INTEGER      NOT NULL,
    configuration_json TEXT        NOT NULL,
    signature         TEXT,            -- detached signature over configuration_json, see DevicePolicySigner
    effective_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_iam_device_policies_tenant_version UNIQUE (tenant_id, version)
);

CREATE INDEX idx_iam_device_policies_tenant ON iam_device_policies (tenant_id, version DESC);

-- Per-application overrides of the tenant policy's default pending/offline
-- behaviour (Section 10.3's "applications" array). application_id matches
-- an oidc_clients or saml_sps row id -- not a foreign key across both
-- possible tables, same "app_kind + app_id" pattern already used by
-- app_group_assignments.
CREATE TABLE iam_device_app_policies (
    id                    UUID PRIMARY KEY,
    policy_id             UUID         NOT NULL REFERENCES iam_device_policies (id) ON DELETE CASCADE,
    application_id        UUID         NOT NULL,
    pending_access        BOOLEAN      NOT NULL DEFAULT FALSE,
    offline_access        BOOLEAN      NOT NULL DEFAULT FALSE,
    offline_grace_seconds INTEGER      NOT NULL DEFAULT 0,
    failure_mode          VARCHAR(16)  NOT NULL DEFAULT 'RISK_BASED'  -- FAIL_OPEN, FAIL_CLOSED, RISK_BASED
);

CREATE INDEX idx_iam_device_app_policies_policy ON iam_device_app_policies (policy_id);

-- Short-lived, single-use authorization minted by POST /enrollment/start
-- once the caller has proven they hold a live IAM session (Section 6.1
-- steps 3-4: "do not collect the user's password inside the agent" --
-- the agent never sees a password, only this opaque transaction id, which
-- it got by directing the user through a normal browser login). Consumed
-- (not deleted, for audit) by POST /enrollment/complete; a second attempt
-- to use the same transaction id is rejected (Section 16 "Enrollment
-- replay" threat).
CREATE TABLE iam_device_enrollment_transactions (
    id          UUID PRIMARY KEY,
    tenant_id   UUID         NOT NULL,
    user_id     UUID         NOT NULL,
    nonce       VARCHAR(255) NOT NULL,  -- proof-of-possession challenge the device key must sign
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ  NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE INDEX idx_iam_device_enrollment_tx_expiry ON iam_device_enrollment_transactions (expires_at);

CREATE TABLE iam_agent_releases (
    id              UUID PRIMARY KEY,
    version         VARCHAR(32)  NOT NULL,
    platform        VARCHAR(16)  NOT NULL,  -- WINDOWS (only value in Phase 1)
    architecture    VARCHAR(16)  NOT NULL,  -- x86_64, aarch64
    package_uri     VARCHAR(1024) NOT NULL,
    checksum        VARCHAR(128) NOT NULL,
    signing_key_id  VARCHAR(255) NOT NULL,
    release_state   VARCHAR(16)  NOT NULL,  -- DRAFT, PILOT, PRODUCTION, RETIRED
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_iam_agent_releases_version_platform UNIQUE (version, platform, architecture)
);
