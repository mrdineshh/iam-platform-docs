CREATE TABLE audit_events (
    event_id             UUID PRIMARY KEY,
    correlation_id       VARCHAR(64) NOT NULL,
    occurred_at          TIMESTAMPTZ NOT NULL,
    tenant_id            UUID NOT NULL,
    actor_type           VARCHAR(16) NOT NULL,
    actor_id             VARCHAR(255) NOT NULL,
    action               VARCHAR(128) NOT NULL,
    result               VARCHAR(16) NOT NULL,
    reason               TEXT,
    source_ip            VARCHAR(64),
    geo                  VARCHAR(128),
    device_id            VARCHAR(255),
    policy_scope_applied VARCHAR(16),
    received_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_events_tenant_id ON audit_events (tenant_id);
CREATE INDEX idx_audit_events_correlation_id ON audit_events (correlation_id);
CREATE INDEX idx_audit_events_occurred_at ON audit_events (occurred_at);
