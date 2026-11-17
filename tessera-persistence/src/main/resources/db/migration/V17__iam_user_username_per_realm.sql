-- V17 — a username is unique per realm (tenant, baseline).
--
-- Login resolves a user by (tenant, baseline, username). Before this, the lookup matched the tenant
-- only, so a user of one baseline could get a session in another baseline of the same tenant, and a
-- name present in two baselines made the lookup non-unique.
--
-- Existing data is checked first, so a clash stops the upgrade with a message naming the problem,
-- not a bare constraint error. iam_user forces row-level security even on its owner, so with no
-- tenant bound this role would see none of its rows: forcing is lifted for the length of the check,
-- inside this migration's transaction, and restored before it commits (the V16 idiom). The ALTER
-- takes an exclusive lock, so no request reads the table in between. The constraint itself is
-- checked against every row, regardless of row-level security. A user without a username is not
-- affected: NULLs never clash.
ALTER TABLE iam_user NO FORCE ROW LEVEL SECURITY;

DO $$
DECLARE
    clashes BIGINT;
BEGIN
    SELECT count(*) INTO clashes FROM (
        SELECT 1 FROM iam_user
        WHERE username IS NOT NULL
        GROUP BY tenant_id, baseline_id, username
        HAVING count(*) > 1
    ) AS duplicated;
    IF clashes > 0 THEN
        RAISE EXCEPTION 'V17: % username(s) occur more than once within one (tenant, baseline) in iam_user; '
            'rename or remove the duplicates, then rerun the migration', clashes;
    END IF;
END $$;

ALTER TABLE iam_user FORCE ROW LEVEL SECURITY;

ALTER TABLE iam_user
    ADD CONSTRAINT uq_iam_user_username UNIQUE (tenant_id, baseline_id, username);
