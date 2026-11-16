package dev.tessera.iam.application.port.out;

import dev.tessera.iam.domain.tenancy.RegisteredTenant;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.smallrye.mutiny.Uni;
import java.util.Optional;

/**
 * Outbound port onto the tenant registry (ADR-IAM-003 D1, ADR-IAM-010 D2): the one narrow read
 * of a tenant's profile and status.
 *
 * <p>The registry sits outside per-tenant row-level security, because it is read before the server
 * knows whether to serve the tenant at all, and only the administrative database role can write
 * it. This port therefore only reads, and returns only what {@link RegisteredTenant} carries.
 */
public interface TenantRegistryPort {

    /**
     * Looks a tenant up.
     *
     * @param tenantId the tenant (never {@code null})
     * @return a {@link Uni} emitting the registered tenant, or empty when it is not registered.
     *         A failed read fails the {@code Uni} with {@link TenantRegistryUnavailableException},
     *         never with an empty result: an unreadable registry is not a missing tenant.
     */
    Uni<Optional<RegisteredTenant>> find(TenantId tenantId);
}
