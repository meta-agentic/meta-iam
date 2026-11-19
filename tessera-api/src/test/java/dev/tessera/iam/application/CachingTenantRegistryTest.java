package dev.tessera.iam.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.tessera.iam.application.port.out.TenantRegistryPort;
import dev.tessera.iam.application.port.out.TenantRegistryUnavailableException;
import dev.tessera.iam.domain.tenancy.RegisteredTenant;
import dev.tessera.iam.domain.tenancy.SecurityProfile;
import dev.tessera.iam.domain.tenancy.TenantId;
import dev.tessera.iam.domain.tenancy.TenantStatus;
import io.smallrye.mutiny.Uni;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("CachingTenantRegistry — iam.tenancy.registry-cache-ttl")
class CachingTenantRegistryTest {

    private static final TenantId TENANT = TenantId.fromString(UUID.randomUUID().toString());
    private static final Duration TTL = Duration.ofSeconds(30);

    /** A clock the test moves by hand. */
    private static final class MovableClock extends Clock {
        private Instant now = Instant.parse("2026-11-19T00:00:00Z");

        void advance(Duration by) {
            now = now.plus(by);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    /** A registry whose answer the test sets, counting reads. */
    private static final class ScriptedRegistry implements TenantRegistryPort {
        final AtomicInteger reads = new AtomicInteger();
        volatile Optional<RegisteredTenant> answer = Optional.empty();
        volatile boolean failing;

        @Override
        public Uni<Optional<RegisteredTenant>> find(TenantId tenantId) {
            return Uni.createFrom().deferred(() -> {
                reads.incrementAndGet();
                if (failing) {
                    return Uni.createFrom().failure(
                            new TenantRegistryUnavailableException(new IllegalStateException("down")));
                }
                return Uni.createFrom().item(answer);
            });
        }
    }

    private static Optional<RegisteredTenant> tenant(TenantStatus status) {
        return Optional.of(new RegisteredTenant(TENANT, SecurityProfile.STANDARD, status));
    }

    private static Optional<RegisteredTenant> read(TenantRegistryPort registry) {
        return registry.find(TENANT).await().indefinitely();
    }

    @Test
    @DisplayName("a registered tenant is served from the cache until the TTL passes")
    void registeredTenant_isCachedForTheTtl() {
        ScriptedRegistry delegate = new ScriptedRegistry();
        MovableClock clock = new MovableClock();
        CachingTenantRegistry cache = new CachingTenantRegistry(delegate, TTL, clock);
        delegate.answer = tenant(TenantStatus.ACTIVE);

        assertThat(read(cache)).isEqualTo(tenant(TenantStatus.ACTIVE));
        delegate.answer = tenant(TenantStatus.SUSPENDED);
        clock.advance(TTL.minusSeconds(1));
        assertThat(read(cache)).as("still within the TTL").isEqualTo(tenant(TenantStatus.ACTIVE));
        assertThat(delegate.reads).hasValue(1);

        clock.advance(Duration.ofSeconds(1));
        assertThat(read(cache)).as("the suspension applies once the TTL has passed")
                .isEqualTo(tenant(TenantStatus.SUSPENDED));
        assertThat(delegate.reads).hasValue(2);
    }

    @Test
    @DisplayName("an absent tenant is not cached, so a newly registered one is served at once")
    void absentTenant_isNotCached() {
        ScriptedRegistry delegate = new ScriptedRegistry();
        CachingTenantRegistry cache = new CachingTenantRegistry(delegate, TTL, new MovableClock());

        assertThat(read(cache)).isEmpty();
        delegate.answer = tenant(TenantStatus.ACTIVE);
        assertThat(read(cache)).isEqualTo(tenant(TenantStatus.ACTIVE));
        assertThat(delegate.reads).hasValue(2);
    }

    @Test
    @DisplayName("a read error is never cached and never defaulted")
    void readError_isNotCached() {
        ScriptedRegistry delegate = new ScriptedRegistry();
        MovableClock clock = new MovableClock();
        CachingTenantRegistry cache = new CachingTenantRegistry(delegate, TTL, clock);
        delegate.failing = true;

        assertThatThrownBy(() -> read(cache)).isInstanceOf(TenantRegistryUnavailableException.class);
        delegate.failing = false;
        delegate.answer = tenant(TenantStatus.ACTIVE);
        assertThat(read(cache)).isEqualTo(tenant(TenantStatus.ACTIVE));
    }

    @Test
    @DisplayName("an expired entry whose re-read fails fails the lookup, not a stale answer")
    void expiredEntry_withFailingReread_fails() {
        ScriptedRegistry delegate = new ScriptedRegistry();
        MovableClock clock = new MovableClock();
        CachingTenantRegistry cache = new CachingTenantRegistry(delegate, TTL, clock);
        delegate.answer = tenant(TenantStatus.ACTIVE);
        read(cache);

        clock.advance(TTL);
        delegate.failing = true;
        assertThatThrownBy(() -> read(cache)).isInstanceOf(TenantRegistryUnavailableException.class);
    }

    @Test
    @DisplayName("a tenant that disappears is dropped from the cache on its next read")
    void tenantThatDisappears_isDropped() {
        ScriptedRegistry delegate = new ScriptedRegistry();
        MovableClock clock = new MovableClock();
        CachingTenantRegistry cache = new CachingTenantRegistry(delegate, TTL, clock);
        delegate.answer = tenant(TenantStatus.ACTIVE);
        read(cache);

        clock.advance(TTL);
        delegate.answer = Optional.empty();
        assertThat(read(cache)).isEmpty();
        delegate.answer = tenant(TenantStatus.SUSPENDED);
        assertThat(read(cache)).isEqualTo(tenant(TenantStatus.SUSPENDED));
    }

    @Test
    @DisplayName("a zero TTL turns the cache off")
    void zeroTtl_readsEveryTime() {
        ScriptedRegistry delegate = new ScriptedRegistry();
        CachingTenantRegistry cache = new CachingTenantRegistry(delegate, Duration.ZERO, new MovableClock());
        delegate.answer = tenant(TenantStatus.ACTIVE);

        read(cache);
        read(cache);
        assertThat(delegate.reads).hasValue(2);
    }

    @Test
    @DisplayName("a negative TTL is refused")
    void negativeTtl_isRefused() {
        assertThatThrownBy(() -> new CachingTenantRegistry(new ScriptedRegistry(), Duration.ofSeconds(-1),
                new MovableClock())).isInstanceOf(IllegalArgumentException.class);
    }
}
