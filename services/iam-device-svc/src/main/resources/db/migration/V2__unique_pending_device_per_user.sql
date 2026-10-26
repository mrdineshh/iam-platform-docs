-- Prevents the race in DeviceService.ensurePending: two concurrent
-- "no existing device, create one" calls for the same tenant/user could
-- both pass the check before either INSERT lands, producing two PENDING
-- devices with different secrets -- one shown on the QR the user scans,
-- the other picked up by verifyTotp's "most recent" lookup. A partial
-- unique index turns the second concurrent INSERT into a DB error instead
-- of a silent duplicate, which the service layer now catches and retries
-- against the row that won.
CREATE UNIQUE INDEX idx_devices_one_pending_per_user
    ON devices (tenant_id, user_id)
    WHERE status = 'PENDING';
