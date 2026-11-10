-- PKCE-style binding (RFC 7636 idea, applied to device enrollment): the
-- agent sends a SHA-256 thumbprint of the public key it is about to
-- register *before* the user signs in, and /enrollment/complete only
-- accepts that exact key. An enrollment transaction id intercepted on the
-- loopback redirect is useless to anyone without the matching private key.
-- Nullable only so this migration is safe against any pre-existing rows;
-- DeviceTrustService requires it on every new transaction.
ALTER TABLE iam_device_enrollment_transactions ADD COLUMN key_thumbprint VARCHAR(64);
