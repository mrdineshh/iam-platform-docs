-- One database per service (BUILD_PLAN.md Section 1, "Database per service").
-- Only runs on first container init against an empty data directory; if the
-- postgres volume already exists, create new databases manually instead
-- (see each service's README for the exact command).
CREATE DATABASE audit_db;
CREATE DATABASE tenant_db;
CREATE DATABASE identity_db;
CREATE DATABASE policy_db;
CREATE DATABASE device_db;
