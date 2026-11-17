-- V18 — what a user record says about a person, for the ID token's standard claims
-- (OIDC Core §5.4): an email address, whether it is verified, and a full name.
--
-- All three are optional: a user without them signs in as before, and the claims are left out.
-- email_verified defaults to false. Only the operator's startup declaration writes these today,
-- and it sets true for an address it declares (administratively verified). A future self-service
-- path must write false until it has sent verification mail.
--
-- The existing iam_user row-level-security policy (V3) is table-level and governs the new columns.
ALTER TABLE iam_user
    ADD COLUMN email          TEXT,
    ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN name           TEXT;

-- A value is either absent or meaningful: never empty, never padded, and an address has one '@'
-- with something on each side and no white space.
ALTER TABLE iam_user
    ADD CONSTRAINT ck_iam_user_email
        CHECK (email IS NULL OR email ~ '^[^@[:space:]]+@[^@[:space:]]+$'),
    ADD CONSTRAINT ck_iam_user_name
        CHECK (name IS NULL OR (name <> '' AND name !~ '^\s|\s$'));
