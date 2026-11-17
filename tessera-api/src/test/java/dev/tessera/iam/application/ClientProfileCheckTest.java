package dev.tessera.iam.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.tessera.iam.application.port.out.TenantRegistryUnavailableException;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.client.ClientUse;
import dev.tessera.iam.domain.client.PublicClient;
import dev.tessera.iam.domain.client.grant.AuthorizationCode;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.RegisteredTenant;
import dev.tessera.iam.domain.tenancy.SecurityProfile;
import dev.tessera.iam.domain.tenancy.TenantId;
import dev.tessera.iam.domain.tenancy.TenantStatus;
import io.smallrye.mutiny.Uni;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("ClientProfileCheck — the profile folded into a client's authentication result")
class ClientProfileCheckTest {

    private static final RealmKey REALM = new RealmKey(TenantId.generate(), new BaselineId(new UUID(0L, 0L)));
    private static final PublicClient CLIENT = new PublicClient(new ClientId(UUID.randomUUID()), REALM,
            Set.of(new AuthorizationCode()), Set.of("https://app.example/cb"));

    private final AtomicInteger reads = new AtomicInteger();

    private ClientProfileCheck on(Optional<RegisteredTenant> answer) {
        return new ClientProfileCheck(tenant -> {
            reads.incrementAndGet();
            return Uni.createFrom().item(answer);
        });
    }

    private static Optional<RegisteredTenant> tenantOn(SecurityProfile profile) {
        return Optional.of(new RegisteredTenant(REALM.tenant(), profile, TenantStatus.ACTIVE));
    }

    private static boolean await(Uni<Boolean> result) {
        return result.await().indefinitely();
    }

    @Test
    @DisplayName("an authenticated client of a standard tenant conforms")
    void standard_conforms() {
        assertThat(await(on(tenantOn(SecurityProfile.STANDARD))
                .andConforms(true, REALM, CLIENT, ClientUse.ACTS_FOR_PERSON))).isTrue();
    }

    @Test
    @DisplayName("a failed authentication stays failed and reads nothing")
    void unauthenticated_readsNothing() {
        assertThat(await(on(tenantOn(SecurityProfile.STANDARD))
                .andConforms(false, REALM, null, ClientUse.ACTS_FOR_ITSELF))).isFalse();
        assertThat(reads).hasValue(0);
    }

    @Test
    @DisplayName("a client of a fapi2 tenant does not conform while fapi2 is not available")
    void fapi2_doesNotConform() {
        assertThat(await(on(tenantOn(SecurityProfile.FAPI2))
                .andConforms(true, REALM, CLIENT, ClientUse.ACTS_FOR_ITSELF))).isFalse();
    }

    @Test
    @DisplayName("a client of an unregistered tenant does not conform")
    void unregistered_doesNotConform() {
        assertThat(await(on(Optional.empty()).andConforms(true, REALM, CLIENT, ClientUse.ACTS_FOR_ITSELF))).isFalse();
    }

    @Test
    @DisplayName("an unreadable registry fails the request")
    void unreadable_fails() {
        ClientProfileCheck down = new ClientProfileCheck(tenant -> Uni.createFrom().failure(
                new TenantRegistryUnavailableException(new IllegalStateException("down"))));
        assertThatThrownBy(() -> await(down.andConforms(true, REALM, CLIENT, ClientUse.ACTS_FOR_ITSELF)))
                .isInstanceOf(TenantRegistryUnavailableException.class);
    }
}
