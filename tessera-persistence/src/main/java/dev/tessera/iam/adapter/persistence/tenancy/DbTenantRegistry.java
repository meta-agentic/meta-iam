package dev.tessera.iam.adapter.persistence.tenancy;

import dev.tessera.iam.adapter.persistence.db.ConnectionFailures;
import dev.tessera.iam.application.CachingTenantRegistry;
import dev.tessera.iam.application.port.out.TenantRegistryPort;
import dev.tessera.iam.application.port.out.TenantRegistryUnavailableException;
import dev.tessera.iam.domain.tenancy.RegisteredTenant;
import dev.tessera.iam.domain.tenancy.SecurityProfile;
import dev.tessera.iam.domain.tenancy.TenantId;
import dev.tessera.iam.domain.tenancy.TenantStatus;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import java.time.Clock;
import java.time.Duration;
import java.util.Optional;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.hibernate.reactive.mutiny.Mutiny;

/**
 * Persistence-backed {@link TenantRegistryPort}: one primary-key read of the {@code tenant} table
 * (V16), which sits outside row-level security, so no tenant is bound for it.
 *
 * <p>It reads only. The application role holds {@code SELECT} alone on the table; registering a
 * tenant is {@link TenantRegistration}'s, run as the administrative role. A failed read is reported
 * as {@link TenantRegistryUnavailableException}, never as an absent tenant. Reads go through
 * {@link CachingTenantRegistry} for {@code iam.tenancy.registry-cache-ttl}.
 */
@ApplicationScoped
public class DbTenantRegistry implements TenantRegistryPort {

    private static final String SELECT_TENANT =
            "SELECT profile, status FROM tenant WHERE tenant_id = :tid";

    // Injected lazily so a Docker-free launcher profile with no datasource stays bootable.
    @Inject
    Instance<Mutiny.SessionFactory> sessionFactory;

    @ConfigProperty(name = "iam.db.read-retries", defaultValue = "1")
    int readRetries;

    /**
     * How long a registered tenant is served from the in-process cache: the longest a suspension
     * takes to apply on one instance. {@code PT0S} turns the cache off.
     */
    @ConfigProperty(name = "iam.tenancy.registry-cache-ttl", defaultValue = "PT30S")
    Duration cacheTtl;

    private volatile TenantRegistryPort cached;

    @Override
    public Uni<Optional<RegisteredTenant>> find(TenantId tenantId) {
        if (tenantId == null) {
            throw new IllegalArgumentException("tenantId must not be null");
        }
        return cache().find(tenantId);
    }

    private TenantRegistryPort cache() {
        TenantRegistryPort current = cached;
        if (current == null) {
            synchronized (this) {
                current = cached;
                if (current == null) {
                    if (cacheTtl.isNegative()) {
                        throw new IllegalStateException(
                                "iam.tenancy.registry-cache-ttl must not be negative, got: " + cacheTtl);
                    }
                    current = new CachingTenantRegistry(this::read, cacheTtl, Clock.systemUTC());
                    cached = current;
                }
            }
        }
        return current;
    }

    private Uni<Optional<RegisteredTenant>> read(TenantId tenantId) {
        // Its own session, as DbRefreshTokenTenantResolver does: created at subscription, so it
        // never joins a session another unit of work has bound to the current Vert.x context.
        Uni<Optional<RegisteredTenant>> read = Uni.createFrom().deferred(() ->
                sessionFactory.get().openSession().chain(session ->
                        session.createNativeQuery(SELECT_TENANT, Object[].class)
                                .setParameter("tid", tenantId.value())
                                .getSingleResultOrNull()
                                .map(row -> toTenant(tenantId, row))
                                .onTermination().call(session::close)));
        return withRetries(read, readRetries)
                .onFailure(failure -> !(failure instanceof TenantRegistryUnavailableException))
                .transform(TenantRegistryUnavailableException::new);
    }

    private static <T> Uni<T> withRetries(Uni<T> read, int retriesLeft) {
        if (retriesLeft <= 0) {
            return read;
        }
        return read.onFailure(ConnectionFailures::isRetryableBeforeWork)
                .recoverWithUni(failure -> ConnectionFailures.pauseBeforeRetry()
                        .chain(() -> withRetries(read, retriesLeft - 1)));
    }

    private static Optional<RegisteredTenant> toTenant(TenantId tenantId, Object[] row) {
        if (row == null) {
            return Optional.empty();
        }
        return Optional.of(new RegisteredTenant(
                tenantId,
                SecurityProfile.fromWireName((String) row[0]),
                TenantStatus.fromWireName((String) row[1])));
    }
}
