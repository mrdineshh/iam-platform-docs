-- Application-specific pending-device access (spec P1-13, section 6.4): for an app that requires a trusted device, may a
-- laptop that is enrolled but still awaiting approval open it? Off by default (pending laptops are refused).
ALTER TABLE oidc_clients ADD COLUMN allow_pending_device BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE saml_sps ADD COLUMN allow_pending_device BOOLEAN NOT NULL DEFAULT FALSE;
