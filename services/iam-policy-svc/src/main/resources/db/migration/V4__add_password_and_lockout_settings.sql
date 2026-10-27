-- Tenant-level sign-in security settings (FR-3.1 password complexity, FR-3.5
-- account lockout). Stored on the TENANT-scope policy row, so the single
-- policy engine remains the one source of configuration (AP-1). All nullable:
-- null means "use the platform default" (see SecuritySettings in
-- PolicyService). They are only meaningful at TENANT scope and are rejected
-- on OU/USER policies.
ALTER TABLE policies
    ADD COLUMN password_min_length        INTEGER,
    ADD COLUMN password_require_uppercase BOOLEAN,
    ADD COLUMN password_require_lowercase BOOLEAN,
    ADD COLUMN password_require_digit     BOOLEAN,
    ADD COLUMN password_require_symbol    BOOLEAN,
    ADD COLUMN lockout_threshold          INTEGER,
    ADD COLUMN lockout_duration_minutes   INTEGER,
    ADD COLUMN lockout_permanent          BOOLEAN;
