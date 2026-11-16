package dev.tessera.iam.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.tessera.iam.application.port.in.TokenUseCase.TokenResult;
import dev.tessera.iam.application.port.out.TenantRegistryPort;
import dev.tessera.iam.application.port.out.TenantRegistryUnavailableException;
import dev.tessera.iam.domain.authcode.AuthorizationError;
import dev.tessera.iam.domain.tenancy.RegisteredTenant;
import dev.tessera.iam.domain.tenancy.SecurityProfile;
import dev.tessera.iam.domain.tenancy.TenantId;
import dev.tessera.iam.domain.tenancy.TenantStatus;
import io.smallrye.mutiny.Uni;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("TenantAdmission — only a registered, active tenant reaches the grant")
class TenantAdmissionTest {

    private static final TenantId TENANT = TenantId.generate();
    private static final TokenResult ISSUED =
            new TokenResult.Issued("at", "Bearer", null, 300, "openid", null);

    private final AtomicInteger grantRuns = new AtomicInteger();

    private Uni<TokenResult> grant() {
        grantRuns.incrementAndGet();
        return Uni.createFrom().item(ISSUED);
    }

    private static TenantAdmission admission(Uni<Optional<RegisteredTenant>> answer) {
        TenantRegistryPort registry = tenant -> answer;
        return new TenantAdmission(registry);
    }

    private static Uni<Optional<RegisteredTenant>> registered(TenantStatus status) {
        return Uni.createFrom().item(Optional.of(new RegisteredTenant(TENANT, SecurityProfile.STANDARD, status)));
    }

    @Test
    @DisplayName("an active tenant runs the grant")
    void active_runsTheGrant() {
        TokenResult result = admission(registered(TenantStatus.ACTIVE)).admit(TENANT, this::grant)
                .await().indefinitely();
        assertThat(result).isEqualTo(ISSUED);
        assertThat(grantRuns).hasValue(1);
    }

    @Test
    @DisplayName("an unregistered tenant is invalid_client and the grant never runs")
    void unregistered_isRefusedBeforeTheGrant() {
        TokenResult result = admission(Uni.createFrom().item(Optional.empty())).admit(TENANT, this::grant)
                .await().indefinitely();
        assertThat(result).isEqualTo(
                new TokenResult.Failed(AuthorizationError.INVALID_CLIENT, "client authentication failed"));
        assertThat(grantRuns).hasValue(0);
    }

    @Test
    @DisplayName("a suspended tenant is invalid_client and the grant never runs")
    void suspended_isRefusedBeforeTheGrant() {
        TokenResult result = admission(registered(TenantStatus.SUSPENDED)).admit(TENANT, this::grant)
                .await().indefinitely();
        assertThat(result).isInstanceOf(TokenResult.Failed.class);
        assertThat(grantRuns).hasValue(0);
    }

    @Test
    @DisplayName("an unreadable registry fails the request and the grant never runs")
    void unreadable_failsTheRequest() {
        Uni<Optional<RegisteredTenant>> down = Uni.createFrom().failure(
                new TenantRegistryUnavailableException(new IllegalStateException("down")));
        assertThatThrownBy(() -> admission(down).admit(TENANT, this::grant).await().indefinitely())
                .isInstanceOf(TenantRegistryUnavailableException.class);
        assertThat(grantRuns).hasValue(0);
    }
}
