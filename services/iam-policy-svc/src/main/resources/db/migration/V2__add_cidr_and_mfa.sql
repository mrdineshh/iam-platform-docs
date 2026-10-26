ALTER TABLE policies
    ADD COLUMN allowed_cidrs             TEXT,
    ADD COLUMN allowed_cidrs_hard_cap    BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN blocked_cidrs             TEXT,
    ADD COLUMN blocked_cidrs_hard_cap    BOOLEAN NOT NULL DEFAULT FALSE,
    -- Nullable, unlike the boolean hard-cap flags above: null means "this
    -- scope doesn't set an opinion", distinct from explicitly set to false.
    -- Required for the merge resolver to correctly fall through to a
    -- broader scope (see PolicyEvaluator's mfaRequired resolution).
    ADD COLUMN mfa_required              BOOLEAN,
    ADD COLUMN mfa_required_hard_cap     BOOLEAN NOT NULL DEFAULT FALSE;
