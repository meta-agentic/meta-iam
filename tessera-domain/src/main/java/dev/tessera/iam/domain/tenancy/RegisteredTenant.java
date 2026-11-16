package dev.tessera.iam.domain.tenancy;

/**
 * A tenant as the tenant registry holds it (ADR-IAM-003 D1, ADR-IAM-010 D2): only the tenant,
 * its security profile and its status, never anything joined from tenant data.
 *
 * @param tenantId the tenant (never {@code null})
 * @param profile  its security profile (never {@code null})
 * @param status   its status (never {@code null})
 */
public record RegisteredTenant(TenantId tenantId, SecurityProfile profile, TenantStatus status) {

    public RegisteredTenant {
        if (tenantId == null) {
            throw new IllegalArgumentException("RegisteredTenant tenantId must not be null");
        }
        if (profile == null) {
            throw new IllegalArgumentException("RegisteredTenant profile must not be null");
        }
        if (status == null) {
            throw new IllegalArgumentException("RegisteredTenant status must not be null");
        }
    }

    /** Whether the tenant may be issued tokens. */
    public boolean isActive() {
        return status == TenantStatus.ACTIVE;
    }
}
