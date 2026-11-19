package dev.tessera.iam.application;

import dev.tessera.iam.application.port.out.TenantRegistryPort;
import dev.tessera.iam.domain.tenancy.RegisteredTenant;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.smallrye.mutiny.Uni;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * An in-process cache in front of a {@link TenantRegistryPort} ({@code iam.tenancy.registry-cache-ttl}).
 *
 * <p>Only a registered tenant is cached, for at most the TTL from the moment it was read. That
 * bounds how long a suspension takes to apply on one instance. An absent tenant is never cached, so
 * a newly registered tenant is served at once. A failed read is never cached either: it fails the
 * request, and the next request reads again. A zero TTL turns the cache off, and every lookup reads
 * the delegate.
 *
 * <p>The realm registry later replaces this cache with its own snapshot (ADR-IAM-011 D5).
 */
public final class CachingTenantRegistry implements TenantRegistryPort {

    private record Entry(RegisteredTenant tenant, Instant expiresAt) {
    }

    private final TenantRegistryPort delegate;
    private final Duration ttl;
    private final Clock clock;
    private final ConcurrentMap<TenantId, Entry> entries = new ConcurrentHashMap<>();

    /**
     * @param delegate the registry read (never {@code null})
     * @param ttl      how long a read tenant is served from the cache; zero turns it off; never
     *                 negative or {@code null}
     * @param clock    the clock the TTL is measured on (never {@code null})
     */
    public CachingTenantRegistry(TenantRegistryPort delegate, Duration ttl, Clock clock) {
        if (delegate == null) {
            throw new IllegalArgumentException("delegate must not be null");
        }
        if (ttl == null || ttl.isNegative()) {
            throw new IllegalArgumentException("ttl must be zero or positive, got: " + ttl);
        }
        if (clock == null) {
            throw new IllegalArgumentException("clock must not be null");
        }
        this.delegate = delegate;
        this.ttl = ttl;
        this.clock = clock;
    }

    @Override
    public Uni<Optional<RegisteredTenant>> find(TenantId tenantId) {
        if (tenantId == null) {
            throw new IllegalArgumentException("tenantId must not be null");
        }
        if (ttl.isZero()) {
            return delegate.find(tenantId);
        }
        return Uni.createFrom().deferred(() -> {
            Entry entry = entries.get(tenantId);
            if (entry != null && clock.instant().isBefore(entry.expiresAt())) {
                return Uni.createFrom().item(Optional.of(entry.tenant()));
            }
            return delegate.find(tenantId).invoke(found -> {
                if (found.isPresent()) {
                    entries.put(tenantId, new Entry(found.get(), clock.instant().plus(ttl)));
                } else {
                    entries.remove(tenantId);
                }
            });
        });
    }
}
