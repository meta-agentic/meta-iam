-- dev-only seed: registers the fixed dev tenant (DevTenant.ID) in the tenant registry, so a
-- `quarkus dev` instance issues it tokens. V16 registers the tenants that exist when it runs, but on
-- a fresh development database it runs before V900 seeds this tenant.
INSERT INTO tenant (tenant_id)
VALUES ('0de00000-0000-4000-a000-00000000d3f0')
ON CONFLICT (tenant_id) DO NOTHING;
