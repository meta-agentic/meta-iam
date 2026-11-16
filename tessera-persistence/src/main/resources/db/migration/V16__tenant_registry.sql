-- V16 — the tenant registry (ADR-IAM-003 D1, ADR-IAM-010 D2).
--
-- One row per tenant the server serves: its security profile and its status. A tenant missing from
-- this table gets no token; it is never defaulted.
--
-- DELIBERATELY NOT tenant-scoped (no row-level security): it is read before the server decides
-- whether to serve the tenant at all, and it holds no tenant data, only (tenant id, profile,
-- status, two timestamps).
--
-- Only the administrative role writes it. That is the role migrations run as (iam_migrator), which
-- also applies the startup registration of declared tenants (TenantRegistration). The application
-- role keeps SELECT only: V1's default privileges granted it INSERT, UPDATE and DELETE on every new
-- table, so they are revoked here, and TenantRegistryIT proves the application role cannot write.
CREATE TABLE tenant (
    tenant_id     UUID         NOT NULL,
    profile       VARCHAR(16)  NOT NULL DEFAULT 'standard',
    status        VARCHAR(16)  NOT NULL DEFAULT 'active',
    registered_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_tenant         PRIMARY KEY (tenant_id),
    CONSTRAINT ck_tenant_profile CHECK (profile IN ('standard', 'fapi2')),
    CONSTRAINT ck_tenant_status  CHECK (status IN ('active', 'suspended'))
);

COMMENT ON TABLE tenant IS
    'Tenant registry: profile and status per tenant; outside RLS; written only by the administrative role (see V16 header).';

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_app') THEN
        EXECUTE 'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON tenant FROM iam_app';
        EXECUTE 'GRANT SELECT ON tenant TO iam_app';
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Register every tenant that already exists
-- ---------------------------------------------------------------------------
-- Without this, the upgrade that ships the registry refuses every tenant at once. A tenant exists
-- when it holds a signing key, a client, a user or a refresh family. The tenant-scoped tables force
-- row-level security even on their owner, so with no tenant bound this role sees none of their
-- rows. Forcing is lifted for the length of this read, inside this migration's transaction, and
-- restored before it commits; the owner is not subject to row-level security while it is lifted.
-- The ALTERs take an exclusive lock, so no request reads these tables in between.
ALTER TABLE signing_key  NO FORCE ROW LEVEL SECURITY;
ALTER TABLE oauth_client NO FORCE ROW LEVEL SECURITY;
ALTER TABLE iam_user     NO FORCE ROW LEVEL SECURITY;

INSERT INTO tenant (tenant_id)
SELECT tenant_id FROM signing_key
UNION SELECT tenant_id FROM oauth_client
UNION SELECT tenant_id FROM iam_user
UNION SELECT tenant_id FROM refresh_family_directory
ON CONFLICT (tenant_id) DO NOTHING;

ALTER TABLE signing_key  FORCE ROW LEVEL SECURITY;
ALTER TABLE oauth_client FORCE ROW LEVEL SECURITY;
ALTER TABLE iam_user     FORCE ROW LEVEL SECURITY;
