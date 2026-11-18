-- Signed agent updates (docs/specs/agent-update-SPEC.md, P1-26). The operator's signature over the release statement, and the
-- installer itself (served only to authenticated agents; integrity comes from the signature, not from where it is stored).
ALTER TABLE iam_agent_releases ADD COLUMN signature TEXT;

CREATE TABLE iam_agent_release_packages (
    release_id UUID PRIMARY KEY REFERENCES iam_agent_releases (id) ON DELETE CASCADE,
    content    BYTEA  NOT NULL,
    size_bytes BIGINT NOT NULL
);
