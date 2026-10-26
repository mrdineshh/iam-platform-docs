ALTER TABLE policies
    ADD COLUMN totp_reenroll_every_login              BOOLEAN,
    ADD COLUMN totp_reenroll_every_login_hard_cap     BOOLEAN NOT NULL DEFAULT FALSE;
