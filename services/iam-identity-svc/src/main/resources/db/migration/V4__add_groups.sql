CREATE TABLE groups (
    id            UUID PRIMARY KEY,
    tenant_id     UUID NOT NULL,
    name          VARCHAR(255) NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_groups_tenant_id ON groups (tenant_id);

-- A user belongs to at most one group, matching the policy engine's
-- existing single-OU-per-evaluation shape (PolicyEvaluator.evaluate takes
-- one ouId, not a list) -- see docs/DECISIONS.md if this needs revisiting
-- for multi-group membership later.
ALTER TABLE users ADD COLUMN group_id UUID;
CREATE INDEX idx_users_group_id ON users (group_id);
