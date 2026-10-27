-- Account lockout state (FR-3.5). Counters live with the credentials they
-- protect. The threshold, duration and permanent-lock choice come from the
-- tenant's policy (iam-policy-svc) at the moment a failed attempt is recorded.
ALTER TABLE users
    ADD COLUMN failed_login_attempts INTEGER     NOT NULL DEFAULT 0,
    ADD COLUMN locked_until          TIMESTAMPTZ,
    ADD COLUMN permanently_locked    BOOLEAN     NOT NULL DEFAULT FALSE;
