package dev.tessera.iam.adapter.rest.support;

import dev.tessera.iam.application.port.out.TenantRegistryPort;
import dev.tessera.iam.application.port.out.TenantRegistryUnavailableException;
import dev.tessera.iam.domain.tenancy.RegisteredTenant;
import dev.tessera.iam.domain.tenancy.SecurityProfile;
import dev.tessera.iam.domain.tenancy.TenantId;
import dev.tessera.iam.domain.tenancy.TenantStatus;
import io.quarkus.test.Mock;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory {@link TenantRegistryPort} for the HTTP tests. Every tenant is registered, standard and
 * active, unless a test says otherwise, so the flows that do not exercise the registry are unaffected.
 */
@Mock
@ApplicationScoped
public class FakeTenantRegistry implements TenantRegistryPort {

    private enum Answer { UNREGISTERED, SUSPENDED, UNAVAILABLE }

    private final Map<TenantId, Answer> overrides = new ConcurrentHashMap<>();

    /** {@code tenant} is not in the registry. */
    public void unregister(TenantId tenant) {
        overrides.put(tenant, Answer.UNREGISTERED);
    }

    /** {@code tenant} is registered and suspended. */
    public void suspend(TenantId tenant) {
        overrides.put(tenant, Answer.SUSPENDED);
    }

    /** Reading {@code tenant} fails as an unreadable registry does. */
    public void failReadsOf(TenantId tenant) {
        overrides.put(tenant, Answer.UNAVAILABLE);
    }

    /** {@code tenant} is back to registered, standard and active. */
    public void restore(TenantId tenant) {
        overrides.remove(tenant);
    }

    @Override
    public Uni<Optional<RegisteredTenant>> find(TenantId tenantId) {
        Answer override = overrides.get(tenantId);
        if (override == null) {
            return Uni.createFrom().item(Optional.of(
                    new RegisteredTenant(tenantId, SecurityProfile.STANDARD, TenantStatus.ACTIVE)));
        }
        return switch (override) {
            case UNREGISTERED -> Uni.createFrom().item(Optional.empty());
            case SUSPENDED -> Uni.createFrom().item(Optional.of(
                    new RegisteredTenant(tenantId, SecurityProfile.STANDARD, TenantStatus.SUSPENDED)));
            case UNAVAILABLE -> Uni.createFrom().failure(
                    new TenantRegistryUnavailableException(new IllegalStateException("registry is down")));
        };
    }
}
