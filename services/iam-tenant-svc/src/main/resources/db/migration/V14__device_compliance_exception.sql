-- Admin-granted, time-limited exception: lets one approved device open trusted-device apps even though it fails
-- the required security checks (docs/DECISIONS.md, 2026-11-18 compliance exception entry). All NULL = no exception.
ALTER TABLE iam_devices ADD COLUMN compliance_exception_until  TIMESTAMPTZ  NULL;
ALTER TABLE iam_devices ADD COLUMN compliance_exception_reason VARCHAR(500) NULL;
ALTER TABLE iam_devices ADD COLUMN compliance_exception_by     VARCHAR(64)  NULL;
